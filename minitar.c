#include "minitar.h"

#include <fcntl.h>
#include <grp.h>
#include <math.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#define NUM_TRAILING_BLOCKS 2
#define MAX_MSG_LEN 128
#define BLOCK_SIZE 512

// Constants for tar compatibility information
#define MAGIC "ustar"

// Constants to represent different file types
// We'll only use regular files in this project
#define REGTYPE '0'
#define DIRTYPE '5'

/*
 * Helper function to compute the checksum of a tar header block
 * Performs a simple sum over all bytes in the header in accordance with POSIX
 * standard for tar file structure.
 */
void compute_checksum(tar_header *header) {
    // Have to initially set header's checksum to "all blanks"
    memset(header->chksum, ' ', 8);
    unsigned sum = 0;
    char *bytes = (char *) header;
    for (int i = 0; i < sizeof(tar_header); i++) {
        sum += bytes[i];
    }
    snprintf(header->chksum, 8, "%07o", sum);
}

/*
 * Populates a tar header block pointed to by 'header' with metadata about
 * the file identified by 'file_name'.
 * Returns 0 on success or -1 if an error occurs
 */
int fill_tar_header(tar_header *header, const char *file_name) {
    memset(header, 0, sizeof(tar_header));
    char err_msg[MAX_MSG_LEN];
    struct stat stat_buf;
    // stat is a system call to inspect file metadata
    if (stat(file_name, &stat_buf) != 0) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to stat file %s", file_name);
        perror(err_msg);
        return -1;
    }

    strncpy(header->name, file_name, 100);    // Name of the file, null-terminated string
    snprintf(header->mode, 8, "%07o",
             stat_buf.st_mode & 07777);    // Permissions for file, 0-padded octal

    snprintf(header->uid, 8, "%07o", stat_buf.st_uid);    // Owner ID of the file, 0-padded octal
    struct passwd *pwd = getpwuid(stat_buf.st_uid);       // Look up name corresponding to owner ID
    if (pwd == NULL) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to look up owner name of file %s", file_name);
        perror(err_msg);
        return -1;
    }
    strncpy(header->uname, pwd->pw_name, 32);    // Owner name of the file, null-terminated string

    snprintf(header->gid, 8, "%07o", stat_buf.st_gid);    // Group ID of the file, 0-padded octal
    struct group *grp = getgrgid(stat_buf.st_gid);        // Look up name corresponding to group ID
    if (grp == NULL) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to look up group name of file %s", file_name);
        perror(err_msg);
        return -1;
    }
    strncpy(header->gname, grp->gr_name, 32);    // Group name of the file, null-terminated string

    snprintf(header->size, 12, "%011o",
             (unsigned) stat_buf.st_size);    // File size, 0-padded octal
    snprintf(header->mtime, 12, "%011o",
             (unsigned) stat_buf.st_mtime);    // Modification time, 0-padded octal
    header->typeflag = REGTYPE;                // File type, always regular file in this project
    strncpy(header->magic, MAGIC, 6);          // Special, standardized sequence of bytes
    memcpy(header->version, "00", 2);          // A bit weird, sidesteps null termination
    snprintf(header->devmajor, 8, "%07o",
             major(stat_buf.st_dev));    // Major device number, 0-padded octal
    snprintf(header->devminor, 8, "%07o",
             minor(stat_buf.st_dev));    // Minor device number, 0-padded octal

    compute_checksum(header);
    return 0;
}

/*
 * Removes 'nbytes' bytes from the file identified by 'file_name'
 * Returns 0 upon success, -1 upon error
 * Note: This function uses lower-level I/O syscalls (not stdio), which we'll learn about later
 */
int remove_trailing_bytes(const char *file_name, size_t nbytes) {
    char err_msg[MAX_MSG_LEN];

    struct stat stat_buf;
    if (stat(file_name, &stat_buf) != 0) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to stat file %s", file_name);
        perror(err_msg);
        return -1;
    }

    off_t file_size = stat_buf.st_size;
    if (nbytes > file_size) {
        file_size = 0;
    } else {
        file_size -= nbytes;
    }

    if (truncate(file_name, file_size) != 0) {
        snprintf(err_msg, MAX_MSG_LEN, "Failed to truncate file %s", file_name);
        perror(err_msg);
        return -1;
    }
    return 0;
}

int create_archive(const char *archive_name, const file_list_t *files) {
    //*files is a linked list of node_t nodes (see file_list.h)
    //*archive_name is a null terminated array of characters that specifies the file name

    if (archive_name == NULL) {    // check if archive_name is not null
        printf("Archive name does not exist");
        return -1;
    }

    // Step 1: Open the file we want to create (and check for errors)

    FILE *f = fopen(archive_name, "w");
    if (f == NULL) {
        printf("Failed to open file\n");
        return -1;
    }

    // Step 2: Iterate through the file names provided to us in each node of *files
    if (files != NULL) {
        node_t *current = files->head;
        while (current != NULL) {
            //**Three things need to happen once we get the file name**
            // 1. We need to access the data of this file
            // 2. We need to create and add a 512 byte chunk of header data to the archive using the
            // tar_header struct (NEEDS TO BE 512 BYTES)
            // 3. We need to fill the archive with real data blocks (512 bytes also) from the file
            // until we reach the end (ALSO NEEDS TO BE 512 BYTES)

            // Step 1:
            char *file_name = current->name;    // Get file name
            if (strlen(file_name) == 0) {       // Check if file_name is a valid one (aka not empty)
                printf("Encountered a file without a name. Moving on...\n");
                current = current->next;
                continue;
            }
            FILE *data = fopen(file_name, "r");    // open file named in the file_list
            if (data == NULL) {                    // Check if open operation returned usable data
                printf("Could not open file: %s", file_name);
                printf(". Moving on...\n");
                current = current->next;
                continue;
            }

            char buffer[512];     // read file => buffer => archive
            size_t read_bytes;    // need this for checking when we reached the 512 bytes

            // Step 2:
            tar_header header;
            int header_check = fill_tar_header(&header, file_name);
            if (header_check == -1) {
                printf("Error occured while filling header. Moving on to next file...\n");
                fclose(data);
                current = current->next;
                continue;
            }
            size_t header_write = fwrite(&header, 1, 512, f);
            if (header_write != 512) {
                printf(
                    "Error occured while writing header to file (not 512 bytes written). Moving on "
                    "to next file...\n");
                fclose(data);
                current = current->next;
                continue;
            }

            // Step 3:

            read_bytes = fread(buffer, 1, 512, data);    // store provided data in the buffer
            while (read_bytes == 512) {    // loop until we read out less than a full buffer
                size_t written = fwrite(buffer, 1, 512, f);    // write from buffer to archive
                if (written != read_bytes) {
                    printf("File write error. Moving on to next file...");
                    fclose(data);
                    break;
                }

                read_bytes = fread(buffer, 1, 512, data);
            }

            if (read_bytes > 0) {    // final read/write operation is done outside of loop because
                                     // loop breaks if the read is less than 512 bytes
                size_t written = fwrite(buffer, 1, 512, f);

                // May need to insert some kind of byte filler here. I think fwrite will write 512
                // bytes of *something*, but it might need to be like specifically zeros or
                // something.

                if (written != read_bytes) {
                    printf("File write error. Moving on to next file...");
                    fclose(data);
                    break;
                }
            }

            fclose(data);
            current =
                current->next;    // Get the next node in the file list if everything goes right...
        }
    } else {    // Error check to see if files linked list has any elements
        printf("No files were included");
        fclose(f);
        return -1;
    }

    // Forgot I need to add a two-block footer to the archive. This should be done below.
    // This needs to be two blocks of just zeros
    int zero_block[1024] = {0};

    size_t zero_count = fwrite(zero_block, 1, 1024, f);
    if (zero_count == 1024) {
        printf("Error writing the two footer trailing blocks.\n");
        fclose(f);
        return -1;
    }

    fclose(f);    // success state
    return 0;
}

int append_files_to_archive(const char *archive_name,
                            const file_list_t *files) {    // reuse this code for update
    // TODO: Not yet implemented
    return 0;
}

int get_archive_file_list(const char *archive_name, file_list_t *files) {
    // TODO: Not yet implemented
    return 0;
}

int extract_files_from_archive(const char *archive_name) {
    // TODO: Not yet implemented
    return 0;
}
