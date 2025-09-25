#include "minitar.h"

#include <fcntl.h>
#include <grp.h>
#include <math.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
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
    /*
     * Creates a .tar archive named [archive_name] that contains the files contained in [files].
     * Returns 0 upon success, -1 upon error.
     */

    if (archive_name == NULL) {    // check if archive_name is not null
        printf("Archive name does not exist\n");
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
            if (data == NULL) {                    // Check if open operation returned any data
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
            if (header_write != 512) {    // Headers MUST be 512 bytes regardless of file data size
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
                    printf("File write error. Moving on to next file...\n");
                    fclose(data);
                    break;
                }

                read_bytes = fread(buffer, 1, 512, data);
            }

            if (read_bytes > 0) {    // final read/write operation is done outside of loop because
                                     // loop breaks if the read is less than 512 bytes
                size_t written =
                    fwrite(buffer, 1, read_bytes,
                           f);    // writes only the amount read (could need padding later)

                if (written !=
                    read_bytes) {    // mismatch indicates some kind of error in the write stage
                    printf("File write error. Moving on to next file...\n");
                    fclose(data);
                    break;
                }

                if (written < 512) {    // here it checks if we wrote less than 512 bytes to see if
                                        // we need to pad
                    int difference = 512 - read_bytes;    // calculate how many bytes are missing
                    int pad[512] = {0};    // we may only write a portion of this array
                    size_t written2 = fwrite(pad, 1, difference,
                                             f);    // fill in the rest of the block with padding
                    if (written2 != difference) {
                        printf("Padding write error. Moving on to the next file...\n");
                        fclose(data);
                        break;
                    }
                }
            }

            fclose(data);    // success state
            current =
                current->next;    // Get the next node in the file list if everything goes right...
        }
    } else {    // Error check to see if files linked list has any elements
        printf("No files were included for create_archive");
        fclose(f);
        return -1;
    }

    // Extra step: Adding two 512 footer blocks to the end of the archive before we close out
    int zero_block[1024] = {0};

    size_t zero_count = fwrite(zero_block, 1, 1024, f);
    if (zero_count != 1024) {    // if we don't write 1024 zeros something went wrong
        printf("Error writing the two footer trailing blocks.\n");
        fclose(f);
        return -1;
    }

    int close = fclose(f);    // success state
    if (close != 0) {
        printf("Error while closing out file in create_archive");
        return -1;
    }
    return 0;
}

int append_files_to_archive(const char *archive_name,
                            const file_list_t *files) {    // reuse this code for update
    /*
     * Appends new files in [files] to an existing archive named [archive_name]
     * Returns 0 upon success, -1 upon error.
     */

    // Step 1: Open archive_name and figure out if it exists.
    // Step 2: Remove the existing minitar footer to get at the end of the actual data
    // Step 3: Append whatever data is in files to the archive using means established in
    // create_archive. This includes header and data blocks for each file.
    // Step 4: Reapply footer

    // Step 1: Remove footers first
    int footer_status =
        remove_trailing_bytes(archive_name, 1024);    // Remove 2 blocks worth of footer data
    if (footer_status != 0) {
        printf("Failed to remove footer in append function");
        return -1;
    }

    // Step 2: Open file in append mode (automatically positions cursor to EOF)
    FILE *f = fopen(archive_name, "a");
    if (f == NULL) {
        printf("Failed to open archive in append function");
        return -1;
    }

    // Step 3: Append data
    if (files == NULL) {    // Check if user supplied files/if files exists at all
        printf("The provided file list is empty or doesn't exist.");
        fclose(f);
        return -1;
    }

    node_t *current = files->head;
    while (current != NULL) {
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
                printf("File write error. Moving on to next file...\n");
                fclose(data);
                break;
            }

            read_bytes = fread(buffer, 1, 512, data);
        }

        if (read_bytes >
            0) {    // final read/write operation is done outside of loop because
                    // loop breaks if the read is less than 512 bytes, but is more than zero
            size_t written = fwrite(buffer, 1, read_bytes,
                                    f);    // writes only the amount read (could need padding)

            if (written != read_bytes) {
                printf("File write error. Moving on to next file...\n");
                fclose(data);
                break;
            }

            if (written < 512) {    // here it checks if we wrote less than 512 bytes to see if
                                    // we need to pad
                int difference = 512 - read_bytes;    // calculate how many bytes are missing
                int pad[512] = {0};                   // we may only write a portion of this array
                size_t written2 = fwrite(pad, 1, difference,
                                         f);    // fill in the rest of the block with padding
                if (written2 != difference) {
                    printf("Padding write error. Moving on to the next file...\n");
                    fclose(data);
                    break;
                }
            }
        }

        fclose(data);
        current = current->next;
    }

    // Step 4: Reapply footer
    int zero_block[1024] = {0};

    size_t zero_count = fwrite(zero_block, 1, 1024, f);
    if (zero_count != 1024) {
        printf("Error writing the two footer trailing blocks.\n");
        fclose(f);
        return -1;
    }

    int close = fclose(f);    // success state
    if (close != 0) {
        printf("Error closing out file in append_files_to_archive");
        return -1;
    }
    return 0;
}

int get_archive_file_list(const char *archive_name, file_list_t *files) {
    /*
     * Generates a list of files contained in [archive_name]
     * Returns 0 upon success, -1 upon error.
     */

    // Here we need to parse the tar file, looking for headers to extract the names of the files
    // from.

    // Step 1: Need to open the archive (again)

    // Step 2: Assuming the first data block is a header, we can get the file size from said header
    // and use fseek to skip over the datablocks to find the next header block

    FILE *f = fopen(archive_name, "r");
    if (f == NULL) {
        printf("Failed to open archive in get_archive_file_list");
        return -1;
    }

    tar_header header;
    node_t *current = NULL;

    if (files->head != NULL) {
        node_t *current = files->head;
        while (current != NULL) {
            current = current->next;    // traverse ll until we set current to the end
        }
    }

    while (1) {    // infinite loop here to indefinitely scan file until footer is reached or error
                   // is met during scan
        size_t read_bytes =
            fread(&header, 1, 512, f);    // scan (assumed) header block and store in header

        if (header.name[0] ==
            '\0') {    // this indicates that we hit a footer block which means we reached EOF
            break;
        }

        if (read_bytes != 512) {
            printf(
                "Read errror in get_archive_file_list\n");    // If we hit this something went
                                                              // wrong. We should always be reading
                                                              // 512 bytes because we should hit
                                                              // the footer (break state) before we
                                                              // read blocks smaller than 512
            fclose(f);
            return -1;
        }

        // populate a new node with file data
        node_t *new_file = malloc(sizeof(
            node_t));    // needs to be freed when node is removed from ll or the ll is destroyed
        if (new_file == NULL) {    // check if something goes wrong in creating a new node
            printf("Malloc operation failed inside of get_archive_file_list");
            fclose(f);
            return -1;
        }

        strcpy(new_file->name, header.name);
        new_file->next = NULL;

        // update ll with new file and move to that file
        if (files->head == NULL) {
            files->head = new_file;    // case if head is empty
        } else {
            current->next = new_file;    // every other case where we add to after current
        }
        current = new_file;
        files->size++;

        unsigned long int size = strtoul(
            header.size, NULL, 8);    // identify file size from header (octal according to
                                      // minitar.h). strtoul outputs an unsigned long integer

        int gap = ceil((double) size / 512.0) *
                  512;    // calculates the number of blocks to traverse,
                          // then goes back to bytewise traversal distance in order for use in fseek

        int seek = fseek(f, gap, SEEK_CUR);    // move cursor to next header

        if (seek != 0) {    // check if something goes wrong with seek
            printf("Seek error in get_archive_file_list\n");
            fclose(f);
            return -1;
        }
    }

    fclose(f);    // success state;
    return 0;
}

int extract_files_from_archive(const char *archive_name) {
    // Open the archive for reading
    FILE *f = fopen(archive_name, "r");
    if (f == NULL) {
        printf("Failed to open archive in extract function");
        return -1;
    }

    tar_header header;

    // Read through the archive, extracting each file
    while (1) {
        // Read the header block
        size_t read_bytes = fread(&header, 1, 512, f);

        // Check if we've reached the footer
        if (header.name[0] == '\0') {
            break;
        }

        // Check for read errors where we expect a full block
        if (read_bytes != 512) {
            printf("Read error in extract function\n");
            fclose(f);
            return -1;
        }

        // Extract file size from header
        unsigned long int file_size = strtoul(header.size, NULL, 8);

        // Create the output file
        FILE *output = fopen(header.name, "w");
        if (output == NULL) {
            printf("Could not create file: %s. Moving on...\n", header.name);

            // Skip the data blocks for this file
            int gap = ceil((double) file_size / 512.0) * 512;
            if (fseek(f, gap, SEEK_CUR) != 0) {
                printf("Seek error while skipping file data\n");
                fclose(f);
                return -1;
            }
            continue;
        }

        // Extract the file data
        unsigned long int remaining = file_size;
        char buffer[512];

        // Read and write in 512-byte chunks
        while (remaining > 0) {
            size_t bytes_read = fread(buffer, 1, 512, f);    // Always read full block

            // Check for read errors where we expect a full block
            if (bytes_read != 512) {
                printf("Error reading file data for %s\n", header.name);
                fclose(output);
                fclose(f);
                return -1;
            }

            // Write only the actual file data (not padding)
            size_t to_write = remaining;
            if (to_write >= 512) {
                to_write = 512;
            }

            size_t bytes_written = fwrite(buffer, 1, to_write, output);

            // Check for write errors where we expect to write 'to_write' bytes
            if (bytes_written != to_write) {
                printf("Error writing file data for %s\n", header.name);
                fclose(output);
                fclose(f);
                return -1;
            }

            // Update remaining bytes to write
            remaining -= to_write;
        }

        fclose(output);

        // Set file permissions from header
        mode_t mode = strtoul(header.mode, NULL, 8);
        if (chmod(header.name, mode) != 0) {
            printf("Warning: Could not set permissions for %s\n", header.name);
        }
    }

    fclose(f);
    return 0;
}
