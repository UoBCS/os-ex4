#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>

#define STR_CHUNK 5

int check_rule(char *line)
{
	struct stat sb;
	int parsing_phase = 1,
		len = strlen(line),
		count = 0,
		total_size = STR_CHUNK,
		i;
	char *filename;

	for (i = 0; i < len; i++) {
		if (line[i] == '\n')
			continue;

		if (line[i] == ' ' && i != 0) {
			filename = malloc(sizeof(char) * total_size);
			parsing_phase = 2;
		}
		else if (parsing_phase == 1) {
			if (!isdigit(line[i]))
				return 1;
		} else {
			if (count >= total_size) {
				total_size += STR_CHUNK;
				filename = realloc(filename, sizeof(char) * total_size);
			}
			filename[count++] = line[i];
		}
	}

	filename[count] = '\0';

	if (stat(filename, &sb) == 0 && sb.st_mode & S_IXUSR)
		return 0;

	return 2;
}

int main(int argc, char *argv[])
{

    
	int option = 0; 
	if(argc <2)
	{
		printf("Usage:\n");
		printf(" %s L            to display rules in kern.log\n", argv[0]);
		printf(" %s W <filename> to load new rules\n", argv[0]);
		return 1;
	}
	else {
		char *proc_filename, *cmd;
		int fd;

		proc_filename = "/proc/firewallExtension";
		if ((fd = open(proc_filename, O_WRONLY)) == -1) {
			printf("Error: cannot open proc file: %d\n", errno);
			return 1;
		}
		cmd = argv[1];

		if(strcmp(argv[1],"L")==0){
			//printf("Print current policy\n");
			if (write(fd, "L", 1) != 1) {
				printf("Error in writing to proc file.\n");
				return 1;
			}
			return 0;
		} else {
			if(strcmp(argv[1],"W")==0){
				//printf("Reading commands\n");
				FILE *fp = fopen(argv[2], "r");
				if (fp == NULL) {
					printf("Error in opening rules file.\n");
					return 1;
				}

				char *line = NULL, *to_send = malloc(sizeof(char) * 2);
				int res, read, idx = 2, len = 0, line_len;
				to_send[0] = 'W';
				to_send[1] = ':';

				while ((read = getline(&line, &len, fp)) != -1) {
					res = check_rule(line);
					if (res == 1) {
						printf("ERROR: Ill-formed file\n");
						break;
					} else if (res == 2) {
						printf("ERROR: Cannot execute file\n");
						break;
					}

					line_len = strlen(line);
					to_send = realloc(to_send, sizeof(char) * (idx + line_len));
					strncpy(to_send + idx, line, line_len); // line_len -> does not include null terminator
					idx += line_len;
				}

				if (!res) {
					to_send[idx] = '\0';
					len = strlen(to_send);

					if (write(fd, to_send, len) != len) {
						printf("Error writing to proc file: %d\n", errno);
						return 1;
					}
				}

				fclose(fp);
				if (to_send)
					free(to_send);
				if (line)
					free(line);

				return res;
			} else{
				printf("Usage:\n ");
				printf("+L to display rules in kern.log\n");
				printf("+\n");
				printf("%s",argv[1]);
				return 1;
			}
		}
	}
}
