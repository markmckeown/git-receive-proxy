#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <event2/event.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <linux/limits.h>
#include <libgen.h>

#include "http_parser.h"

#define BUFFER_READ_SIZE 8192

/**
 * mark.mckeown@wandisco.com
 *
 * Copyright Wandisco, 2014
 *
 * This source code is governed by a GPL2 license
 * found in LICENSE file.
 */


static SHA_CTX sha_ctx;
static char buffer[BUFFER_READ_SIZE];
static char tmp_file_name[PATH_MAX];
static char *tmp_file_template = "/tmp/packfile.tmp.XXXXXX";
static char *packfile_template = "/tmp/";
static char *dir = NULL;
static FILE *logfile = NULL;
static int pf_fd = -1;
static bool http_open = false;
static int http_fd = -1;
static int http_server = -1;
static int http_finished = 0;
static int grp_stop = 0;


/**
 * HTTP header we use when talking to the java service.
 * Note we always send it chunked data.
 */
const char* post_string =
		"POST /git-ms/%s/git-receive-pack HTTP/1.1\r\n"
		"User-Agent: git/1.8.2.396.g36b63d6.dirty\r\n"
		"Host: 127.0.0.1:8080\r\n"
		"Content-Type: application/x-git-receive-pack-request\r\n"
		"Accept: application/x-git-receive-pack-result\r\n"
		"Transfer-Encoding: chunked\r\n"
		"\r\n";


/**
 * State of the parser
 */
enum txn_state {
    TXN_PARSING_COMMAND_HEADER = 0,
    TXN_PARSING_COMMAND_BODY,
    TXN_PARSING_PACKFILE
};


static enum txn_state txn_state = TXN_PARSING_COMMAND_HEADER;

/**
 * Parser used to parser the data coming from git-send-pack.
 * Splits the commands and the packfile.
 */
struct gsp_parser {
    char       header_buffer[4];
    uint8_t    header_buffer_size;
    uint32_t   body_size;
    uint32_t   body_read;
    uint32_t   command_count;
    uint64_t   packfile_size;

    char       pack_header_buffer[4];
    uint8_t    pack_header_read;
    bool       pack_header_done;

    // The packfile trailer is the SHA1 of the previous
    // bytes in the packfile.
    unsigned char   pack_trailer[20];
    char             pack_sha[50];
    uint8_t          pack_trailer_size;
};

/**
 * Global parser
 */
static struct gsp_parser parser = {
    .header_buffer_size = 0,
    .body_size = 0,
    .body_read = 0,
    .packfile_size = 0,
    .command_count = 0,
    .pack_header_read = 0,
    .pack_header_done = false
};


/**
 * Struct to manage the connections between
 * git-send-pack and git-receive-pack. As we use
 * pipes there are multiple connections in each
 * direction.
 * grp - git-receive-pack
 * gsp - git-send-pack
 */
struct connections {
    // event base for connections
    struct event_base *event_base;
    struct event *grp_read_event;
    struct event *grp_err_read_event;
    struct event *gsp_read_event;

    // Connection to git-send-pack
    int from_gsp;
    int to_gsp;
    int to_gsp_err;

    // Connection to git-receive-pack
    int from_grp;
    int from_grp_err;
    int to_grp;

    // Bools used to record if streams closed
    bool from_gsp_closed;
    bool from_grp_closed;
    bool from_grp_err_closed;
};


/**
 * Global connections object.
 */
static struct connections connections = {
    .event_base = NULL,
    .grp_read_event = NULL,
    .grp_err_read_event = NULL,
    .gsp_read_event = NULL,

    .from_gsp = -1,
    .to_gsp = -1,
    .to_gsp_err = -1,

    .from_grp = -1,
    .from_grp_err = -1,
    .to_grp = -1,

    .from_gsp_closed = false,
    .from_grp_closed = false,
    .from_grp_err_closed = false,
};




/**
 * Write helper function. 
 */
ssize_t xwrite(int fd, const void *buf, size_t len)
{
    ssize_t nr;
    while (1) {
        nr = write(fd, buf, len);
        if ((nr < 0) && (errno == EAGAIN || errno == EINTR))
            continue;
        return nr;
    }

    // Never get here, but gcc -WExtra complains unless we return
    return nr;
}

/**
 * Write to the http server. Also writes to the HTTP
 * log file.
 */
void http_write(const void* buffer, ssize_t len)
{
	ssize_t written = 0;

	// Write to the http log file. Assumes all written
    written = xwrite(http_fd, buffer, len);
    assert(written == len);

    // Write to the HTTP server. Note we do blocking
    // write
    do {
    	written = xwrite(http_server, buffer, len);
    	if (written <= 0) {
    		break;
    	}
    	buffer += written;
    	len    -= written;
    } while (len > 0);


    return;
}

/**
 * Connect to the HTTP server, returns -1 if it cannot connect.
 */
int
connect_http_server()
{
	int ret = 0;
	int my_errno = 0;
	struct sockaddr_in  server;

	http_server = socket(AF_INET,SOCK_STREAM,0);
	assert (http_server != -1);

	server.sin_family = AF_INET;
	server.sin_port = htons(8080);
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(server.sin_zero, 0, sizeof(server.sin_zero));

	ret = connect(http_server, (struct sockaddr *)&server, sizeof(server));
	if (ret == -1) {
		// Save errorno as we are going to do a couple of writes with it
		// and it will change
		my_errno = errno;
		// The stderr output will appear on the client
		fprintf(stderr, "Could not connect to HTTP server, %s.\n", strerror(my_errno));
		fprintf(logfile, "Could not connect to HTTP server, %s.\n", strerror(my_errno));
		close(http_server);
		http_server = -1;
	}

	http_fd = open("/tmp/http_proxy.log",  O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
	assert(http_fd != -1);

	return ret;
}

/**
 * Write the HTTP header.
 */
#define HEADER_BUFFER_SIZE 4096
void open_http_stream(char *dir)
{
    char header_buffer[HEADER_BUFFER_SIZE];
    int length = 0;


    memset(header_buffer, 0, HEADER_BUFFER_SIZE);
    length = snprintf(header_buffer, HEADER_BUFFER_SIZE, post_string, dir);
    assert(length > 0);
    assert(length < HEADER_BUFFER_SIZE);

    http_write(header_buffer, length);

    return;
}

/**
 * Write some data to the HTTP server. This will write
 * the data as a HTTP chunk
 */
void write_http_stream(char *buffer, int length)
{
	char chunk_header[20];
	int size = 0;

	size = snprintf(chunk_header, 20, "%x\r\n", length);
	assert(size < 20);

    http_write(chunk_header, size);
    http_write(buffer, length);
    http_write("\r\n", 2);

    return;
}



/**
 * http_parser callback. Invoked at the end of the response
 * message from the http server.
 */
int
http_message_complete(http_parser __attribute__((unused)) *parser)
{
	http_finished = 1;
	return 0;
}

/**
 * http_parser callback. Invoked when we get some body from the
 * http server
 */
int
http_message_body(http_parser __attribute__((unused)) *parser,
					const char *buffer, size_t length)
{
	ssize_t ret = 0;
	// return the body to git-send-pack
	ret = write(connections.to_gsp, buffer, length);
	fprintf(logfile, "Wrote [%zu] of [%zu] to gsp\n", ret, length);

	return 0;
}

/**
 * This should be called when we have sent the complete HTTP request
 * to the HTTP server. It waits for the response from the HTTP server
 */
void close_http_stream()
{
	char chunk_header[20];
	char read_buffer[4096];
	int length = 0;
	http_parser parser;
	http_parser_settings settings;

	// Setup the http_parser for handling the HTTP
	// response
	memset(&settings, 0, sizeof(http_parser_settings));
	settings.on_message_complete = http_message_complete;
	settings.on_body = http_message_body;
	http_parser_init(&parser, HTTP_RESPONSE);

	// Create the terminating chunk header
	int size = 0;
	size = snprintf(chunk_header, 20, "%x\r\n", 0);
	assert(size < 20);

	// Write the terminating chunk to the HTTP server
    http_write(chunk_header, size);
    http_write("\r\n", 2);


    // Now read the response from the HTTP server and
    // send it to git-send-pack. The read from the HTTP
    // server is a blocking read.
    for (;;) {
    	length = read(http_server, read_buffer, 4096);
    	if (length > 0) {
    		// Take a copy of the response for our logs.
    		write(http_fd, read_buffer, length);
    	}
    	// Parse the response. Will invoke the http_parser
    	// callbacks
    	if (length >= 0) {
    		http_parser_execute(&parser, &settings, read_buffer, length);
    		if (http_finished) {
    			break;
    		}
    	}
    	// Error with socket.
    	if (length < 0) {
    		fprintf(logfile, "Error reading from HTTP server, %s\n", strerror(errno));
    		break;
    	}
    }

    // Once we have read the response and sent the contents back to
    // git-send-pack we can exit the event loop.
    close(http_fd);
    close(http_server);
    event_base_loopbreak(connections.event_base);

	return;
}




/**
 * For debugging we currently use a log file that is dumped into
 * tmp.
 */
static void open_log_file()
{
	int ret = 0;
    logfile = fopen("/tmp/grp_proxy.log", "w+");
    assert(logfile != NULL);
    // Don't buffer the log file
    setvbuf(logfile, NULL, _IONBF, 0);
    assert(ret == 0);
    return;
}


/**
 * We save the pack file into a file in tmp. First we write it to
 * a temporary file, then rename it. This creates and opens the
 * temp file.
 */
static void open_pack_file()
{
    memset(tmp_file_name, 0, PATH_MAX);
    strncpy(tmp_file_name, tmp_file_template, strlen(tmp_file_template));
    pf_fd = mkstemp(tmp_file_name);

    assert(pf_fd != -1);
    return;
}

/**
 * Utility function for closing pipes.
 */
static void 
close_pair(int fd[2])
{
    close(fd[0]);
    close(fd[1]);
}


/**
 * Utility function for making connection non-blocking.
 */
void
make_non_blocking(int fd)
{
    int flags = 0;

    flags = fcntl(fd, F_GETFL, 0);
    assert(flags != -1);
    assert(fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    return;
}


/**
 * Given the 4 byte length string from the git command
 * turn it into a real number. NB git has a internal limit
 * of 65K for a command size.
 */
static 
int packet_length(const char *linelen)
{
    int n;
    int len = 0;

    for (n = 0; n < 4; n++) {
        unsigned char c = linelen[n];
        len <<= 4;
        if (c >= '0' && c <= '9') {
            len += c - '0';
            continue;
        }
        if (c >= 'a' && c <= 'f') {
            len += c - 'a' + 10;
            continue;
        }
        if (c >= 'A' && c <= 'F') {
            len += c - 'A' + 10;
            continue;
        }
        return -1;
    }
    return len;
}


/**
 * Convert a SHA1 into a string that can be printed.
 */
static void 
sha1_to_hex(const unsigned char *sha1, char *buffer)
{
    static const char hex[] = "0123456789abcdef";
    int i;

    for (i = 0; i < 20; i++) {
        unsigned int val = *sha1++;
        *buffer++ = hex[val >> 4];
        *buffer++ = hex[val & 0xf];
    }
    *buffer = '\0';

    return;
}


/**
 * We may have read all of the pack file from git-send-pack.
 * git-send-pack closes the pipe it writes to when it has
 * sent all of the pack file - this is the hint that we have
 * got all of the pack file. However, the connection
 * could be closed for some other issue, we check by making sure
 * the SHA1 trailer at the end of the packfile matches with
 * what we got.
 */
static void
process_send_pack_finish()
{
    int ret = 0;
    unsigned char sha[20];
    char packfile[PATH_MAX];

    // Was there any packfile? If not then no point
    // doing anything
    if (pf_fd == -1) {
    	goto out;
    }

    ret = SHA1_Final(sha, &sha_ctx);
    assert(ret == 1);

    // Record the SHA as hex in the parser
    sha1_to_hex(parser.pack_trailer, parser.pack_sha);

    // Now compare the SHA1 we calculated with the trailer
    // from the packfile.
    ret = memcmp(sha, parser.pack_trailer, 20);
    if (ret != 0) {
        fprintf(logfile, "Packfile corrupt.\n");
        // get rid of the corrupt packfile.
        unlink(tmp_file_name);
        goto out;
    }

    // Sync the packfile
    fsync(pf_fd);

    // Move the tmp file to the target location
    memset(packfile, 0, PATH_MAX);
    strncpy(packfile, packfile_template, strlen(packfile_template));       
    strncpy(packfile + strlen(packfile_template), parser.pack_sha,
                    strlen(parser.pack_sha));
    strncpy(packfile + strlen(packfile_template) + strlen(parser.pack_sha),
                    ".pack", strlen(".pack"));
    ret = rename(tmp_file_name, packfile);
    assert(ret == 0);


    fprintf(logfile, "Command Count: [%lu] Packfile Size: [%llu]\n",
            (long unsigned) parser.command_count,
            (long long unsigned) parser.packfile_size);
    fprintf(logfile, "Pack SHA1: [%s]\n",  parser.pack_sha);

out:
	if (pf_fd != -1) {
		close(pf_fd);
	}
    return;
}



/**
 * Whenever we get packfile data we record the last 20 bytes as that
 * might be the SHA1 trailer.
 */
static void
check_pack_trailer(char *buffer, int length)
{
    int ret = 0;
    int offset = 0;
    int overhang = 0;

    // Incoming buffer is greater than 20, save last 20 bytes
    // from buffer and get out
    if (length >= 20) {
        offset = length - 20;
        // We are evicting the trailer buffer, need to SHA1
        // those bytes
        if (parser.pack_trailer_size > 0) {
        	ret = SHA1_Update(&sha_ctx, parser.pack_trailer,
        			parser.pack_trailer_size);
        }
        memcpy(parser.pack_trailer, buffer + offset, 20);
        parser.pack_trailer_size = 20;
        ret = SHA1_Update(&sha_ctx, buffer, offset);
        assert(ret == 1);
        goto out;
    }


    // What we have already and what is in the buffer is less
    // then twenty bytes - just add the buffer to what we have
    // stored already.
    if ((parser.pack_trailer_size + length) <= 20) {
        memcpy(parser.pack_trailer + parser.pack_trailer_size,
                    buffer, length);
        parser.pack_trailer_size = parser.pack_trailer_size + length;
        // Nothing evicted
        goto out;
    }

    // What we have and what is in the buffer is greater than 20,
    // need to throw away some of the old bytes
    overhang = (parser.pack_trailer_size + length) - 20;
    // Add the bytes we throw away to the SHA1
    ret = SHA1_Update(&sha_ctx, parser.pack_trailer, overhang);
    assert(ret == 1);
    memmove(parser.pack_trailer, parser.pack_trailer + overhang,
                    parser.pack_trailer_size - overhang);
    parser.pack_trailer_size -= overhang;
    memcpy(parser.pack_trailer + parser.pack_trailer_size,
                buffer, length);

out:
    return;
}



/**
 * We have received more packfile data.
 */
static void
process_send_pack_packfile(char *buffer, int length)
{
    size_t ret;
    int ret_t;
    int required_length = 0;

    // This indicates whether this is the first time we have
    // got packfile data.
    if (pf_fd == -1) {
        open_pack_file();
        ret_t = SHA1_Init(&sha_ctx);
        assert(ret_t == 1);
    }

    // Check PACK header. We want to check the first four bytes
    // of the pack file is PACK.
    if (!parser.pack_header_done) {
        required_length = 4 - parser.pack_header_read;
        // Do we have enough bytes to make the check?
        if (length >= required_length) {
            memcpy(parser.pack_header_buffer + parser.pack_header_read,
                    buffer, required_length);
            ret_t = strncmp(parser.pack_header_buffer, "PACK", 4);
            assert(ret_t == 0);
            parser.pack_header_done = true;
        } else {
        	// Not enough bytes to make check
            memcpy(parser.pack_header_buffer + parser.pack_header_read,
                    buffer, length);
            parser.pack_header_read += length;
        }
    }

    // dump buffer to tmp file
    ret = write(pf_fd, buffer, length);
    assert(ret == (size_t) length);
 
    // record the last twenty bytes...
    check_pack_trailer(buffer, length);
    parser.packfile_size += length;

    return;
}


/**
 * This function is called when we are processing data from
 * git-send-pack and we are processing the commands. We think
 * of the commands of having two parts the header (the 4 bytes
 * that hold the length of the command) and the body - the rest
 * of the command.
 */
static void
process_send_pack_init_state(char *buffer, int length)
{
    int required_length = 0;

    for (;;) {
    	// TXN_PARSING_COMMAND_HEADER means we are trying to
    	// get the four byte length header
        if (txn_state == TXN_PARSING_COMMAND_HEADER) {
            required_length = 4 - parser.header_buffer_size;

            if (length >= required_length) {
                // Enough data to get header
                memcpy(parser.header_buffer + parser.header_buffer_size, 
                            buffer, required_length);
                parser.header_buffer_size = 4;
            } else {
                // Not enough data to get header, record what we can and spin
                memcpy(parser.header_buffer + parser.header_buffer_size, 
                            buffer, length);
                parser.header_buffer_size += length;
                break;
            }

            // We have enough data to process the header..
            length -= required_length;
            buffer += required_length;
            parser.body_size = packet_length(parser.header_buffer);
            // Zero body size means we have finished parsing the commands
            // and we can move to parsing the packfile
            if (parser.body_size == 0) {
                txn_state = TXN_PARSING_PACKFILE;
                break;
            }
            // The length includes the header, need to trim 4 bytes
            parser.body_size -= 4;
            txn_state = TXN_PARSING_COMMAND_BODY;
        }

        // TXN_PARSING_COMMAND_BODY - pasring the body of the command.
        required_length = parser.body_size - parser.body_read;

        if (length >= required_length) {
            // Enough in buffer for complete command body.
            length -= required_length;
            buffer += required_length;
            memset(parser.header_buffer, 0, 4);
            parser.header_buffer_size = 0;
            parser.body_size = 0;
            parser.body_read = 0;
            parser.command_count++;
            txn_state = TXN_PARSING_COMMAND_HEADER;
        } else {
            // Not enough for full body...spin
            parser.body_read += length;
            break;
        }
    }


    // Have we changed state? And is there more data?
    if (txn_state == TXN_PARSING_PACKFILE
    		&& length > 0) {
    		process_send_pack_packfile(buffer, length);
    }

    return;
}



/**
 * We have got data from the git-send-pack - process it depending
 * on the state of the parser
 */
static void
process_send_pack_buffer(char *buffer, int size)
{
    if (txn_state == TXN_PARSING_COMMAND_HEADER ||
    		txn_state == TXN_PARSING_COMMAND_BODY) {
        process_send_pack_init_state(buffer, size);
    } else {
        process_send_pack_packfile(buffer, size);
    }    

    if (!http_open) {
    	open_http_stream(dir);
    	http_open = true;
    	// Need to close the the git-receive-proxy
    	grp_stop = 1;
    }

    write_http_stream(buffer, size);

    
    return;
}



/**
 * We only care about data coming from git-send-pack. We don't
 * process anything from git-receive-pack yet.
 */
static void
process_buffer(int from, char* buffer, int size)
{
    // Only interested in the stuff coming from the send-pack
    if (from == connections.from_gsp) {
        process_send_pack_buffer(buffer, size);
    } 

    return;
}

/**
 * A connection close has occurred. Need to reset the connection state
 * machine. We can think of the system as having three streams:
 *
 *   git-send-pack -> stdin  proxy -> stdin  git-receive-pack
 *   git-send-pack <- stdout proxy <- stdout git-receive-pack
 *   git-send-pack <- stderr proxy <- stderr git-receive-pack
 *
 * Once one part of a stream is closed then we can close the other
 * part and that stream is done.
 *
 * Once all three streams are closed we can tell libevent to stop
 * and we can exit.
 *
 */
static void
handle_close(int fd)
{
    int ret = 0;

    // The stream from git-receive-pack to git-send-pack has
    // closed.
    if (fd == connections.from_grp 
            || fd == connections.to_gsp) {
        close(connections.from_grp);
        close(connections.to_gsp);
        connections.from_grp_closed = true;
        event_del(connections.grp_read_event);
    }


    if (fd == connections.from_grp_err
            || fd == connections.to_gsp_err) {
        close(connections.from_grp_err);
        close(connections.to_gsp_err);
        connections.from_grp_err_closed = true;
        event_del(connections.grp_err_read_event);
    }


    // The stream from git-send-pack to git-receive-pack has
    // closed.
    if (fd == connections.from_gsp
    		|| fd == connections.to_grp) {
        close(connections.from_gsp);
        close(connections.to_grp);
        connections.from_gsp_closed = true;
        event_del(connections.gsp_read_event);

        // We can tell the parser that we do not think
        // there is any more packfile coming.
        process_send_pack_finish();
        close_http_stream();
    }
    
    // All streams of the proxy are closed...time to exit the event loop
    if (connections.from_grp_closed
    		&& connections.from_grp_err_closed
    		&& connections.from_gsp_closed) {
    	fprintf(stderr, "All streams closed, can exit.\n");
    	ret = event_base_loopbreak(connections.event_base);
    	assert(ret == 0);
    }

    return;
}


/**
 * We have been told to move data from one connection to another. Read
 * from the first connection and write to the other connection.
 */
static void
write_from_to(int from, int to) 
{
    int ret_t = 0;
    ssize_t nr = 0;

    // Reads are non-blocking, we read until we get EAGAIN. writes
    // are blocking so we will block until the write completes
    for(;;) {
read_again:
    	ret_t = read(from, buffer, BUFFER_READ_SIZE);
    	if ((ret_t < 0) && (errno == EINTR)) {
    		goto read_again;
    	}

    	if ((ret_t < 0) && (errno == EAGAIN)) {
    		break;
    	}

    	fprintf(logfile, "Read [%d] bytes from [%d]\n", ret_t, from);

    	// read error....
    	if (ret_t == -1) {
    		fprintf(logfile, "Error reading from [%d], %s\n", from, strerror(errno));
    		handle_close(from);
    		break;
    	}

    	// pipe closed....
    	if (ret_t == 0) {
    		fprintf(logfile, "Pipe [%d] has closed\n", from);
    		handle_close(from);
    		break;
    	}

    	// Process the data we have just read - this does not change the buffer
    	process_buffer(from, buffer, ret_t);
    	if (grp_stop) {
    		// We are no longer talking to the git-receive-pack process...
    		// we going to the HTTP server from now on.
    		continue;
    	}

write_again:
    	nr = write(to, buffer, ret_t);
    	if ((nr < 0) && (errno == EAGAIN || errno == EINTR)) {
    		goto write_again;
    	}

    	fprintf(logfile, "Wrote [%zu] bytes to [%d]\n", nr, to);

    	// write error....
    	if (nr == -1) {
    		handle_close(to);
    		break;
    	}
    }

    return;
}


/**
 * Read callback for libevent. There is something to read from
 * git-receive-pack stdout.
 */
static void 
grp_read_callback(evutil_socket_t fd, 
                              __attribute__((unused)) short what, 
                              __attribute__((unused)) void *arg)
{
	//read from git-receive-pack and send to git-send-pack
    write_from_to(fd, connections.to_gsp);
    return;
}

/**
 * Read callback for libevent. There is something to read from
 * git-receive-pack err.
 */
static void
grp_read_err_callback(evutil_socket_t __attribute__((unused)) fd,
                              __attribute__((unused)) short what,
                              __attribute__((unused)) void *arg)
{
	//read from git-receive-pack and send to git-send-pack
    write_from_to(fd, connections.to_gsp_err);
    return;
}


/**
 * Read callback for libevent. There is something to read from
 * git-send-pack.
 */
static void 
gsp_read_callback(evutil_socket_t fd, 
                              __attribute__((unused)) short what, 
                              __attribute__((unused))void *arg)
{
	//read from git-send-pack and write to git-receive-pack
    write_from_to(fd, connections.to_grp);
    return;
}


int
main(int argc, char **argv) {
    int ret = 0;
    int i = 0;
    int fdin[2], fdout[2], fderr[2];
    pid_t pid;
    char **new_args = NULL;
    char *cmd = "git-receive-pack";

    open_log_file();

    // If we cannot connect to the HTTP server - then
    // exit
    ret = connect_http_server();
    if (ret != 0) {
    	goto err;
    }

    // Set up some pipes for the fork thats coming
    ret = pipe(fdin);
    assert(ret == 0);

    ret = pipe(fdout);
    assert(ret == 0);

    ret = pipe(fderr);
    assert(ret == 0);

    // Handle SIGPIPE on write..ignore and detect when writing.
    signal(SIGPIPE, SIG_IGN);

    // dump the comand line args we were called with
    for(i = 0; i < argc; i++) {
        fprintf(logfile, "[%s] ", argv[i]);
    }
    fprintf(logfile, "\n");
    dir = argv[argc-1];

    // Rebuild the command line args for git-receive-pack
    // that we are going to fork off...
    new_args = calloc(argc + 1, sizeof(char *));
    assert(new_args != NULL);
    for(i = 1; i < argc; i++){
        new_args[i] = argv[i];
    }
    new_args[0] = cmd;

    
    fflush(NULL);
    pid = fork();
    assert(pid != -1);

    // Child Process - this will run git-receive-pack
    if (pid == 0) {
    	fclose(logfile);

        // dup stdin - connect stdin from git-receive-pack
    	// to fdin[0]
        ret = dup2(fdin[0], 0);
        assert(ret != -1);
        close_pair(fdin);

        // dup stderr - connect stderr from git-receive-pack
        // to fderr[1]
        ret = dup2(fderr[1], 2);
        assert(ret != -1);
        close_pair(fderr);

        // dup stdout - connect fdout from git-receive-pack
        // to fdout[1]
        ret = dup2(fdout[1], 1);
        assert(ret != -1);
        close_pair(fdout);

        // replace current process with git-receive-pack
        ret = execvp("git", new_args);
        // only get here if execvp fails...
        return ret;
    }

    // Parent Process
    // fork failed.
    if (pid < 0) {
        // close pipes and get out...
    	close_pair(fdin);
    	close_pair(fderr);
    	close_pair(fdout);
    	goto err;
    }

    // Need to close the parts of the pipes we are
    // not using in the parent
    close(fdout[1]);
    close(fderr[1]);
    close(fdin[0]);


    // Need to set up connection state machine
    memset(&connections, 0, sizeof(struct connections));

    // Link up the git-send-pack connections - we have hooked
    // in the err stream but not sure if it is used.
    connections.from_gsp = 0;
    connections.to_gsp = 1;
    connections.to_gsp_err = 2;
    connections.from_grp = fdout[0];
    connections.from_grp_err = fderr[0]; 
    connections.to_grp = fdin[1];


    // Now set the inputs non-blocking. Writes
    // will be blocking.
    make_non_blocking(connections.from_grp);
    make_non_blocking(connections.from_grp_err);
    make_non_blocking(connections.from_gsp);

    // Create our event base
    connections.event_base = event_base_new();
    assert(connections.event_base != NULL);

    // Add event for handling stuff coming from git-receive-pack stdout
    connections.grp_read_event = event_new(connections.event_base, 
                                           connections.from_grp, 
                                           EV_READ|EV_PERSIST, 
                                           grp_read_callback, NULL);    
    assert(connections.grp_read_event != NULL);

    // Add event for handling stuff coming from git-receive-pack stderr
    connections.grp_err_read_event = event_new(connections.event_base, 
                                           connections.from_grp_err, 
                                           EV_READ|EV_PERSIST, 
                                           grp_read_err_callback, NULL);
    assert(connections.grp_err_read_event != NULL);

    // Add event for handling stuff coming from git-send-pack
    connections.gsp_read_event = event_new(connections.event_base, 
                                           connections.from_gsp, 
                                           EV_READ|EV_PERSIST, 
                                           gsp_read_callback, NULL);    
    assert(connections.gsp_read_event != NULL);


    // Add all the events to base
    ret = event_add(connections.grp_read_event, NULL);
    assert(ret == 0);
    ret = event_add(connections.grp_err_read_event, NULL);
    assert(ret == 0);
    ret = event_add(connections.gsp_read_event, NULL);
    assert(ret == 0);

    // Enter event loop
    event_base_loop(connections.event_base, 0);

    // Release event stuff...
    event_free(connections.grp_read_event);
    event_free(connections.grp_err_read_event);
    event_free(connections.gsp_read_event);
    event_base_free(connections.event_base);

err:
    fclose(logfile);
    free(new_args);
    return ret;
}

