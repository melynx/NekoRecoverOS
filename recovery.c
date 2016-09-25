#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

#include "verifier/verifier.h"

const char *ota_path = "/home/seed/ota/ota.zip";

int signature_check = 1;

char get_single_char()
{
	char c = getchar();
	char d = c;
	while((d != '\n' && c != EOF)) d = getchar();
	return c;
}

void enter_key()
{
	printf("Press enter to continue.");
	get_single_char();	
}

void print_logo()
{
	char c;
	FILE *file = fopen("/bin/logo.txt", "r");

	system("clear");

	if (file) {
		while ((c = getc(file)) != EOF)
			putchar(c);
		fclose(file);
	}
}

void print_menu()
{
	char *menu_string =     "1. Flash OTA.zip.\n"
				"2. Toggle Signature check.\n"
				"3. Enter usermode Shell.\n"
				"4. Enter root Shell.\n"
				"5. Restart.\n"
				"\n"
				"Please enter an option :";

	print_logo();
	printf("%s", menu_string);
}

void disable_check()
{
	signature_check = !signature_check;
	if (signature_check)
	{
		printf("\nSignature verification is enabled!\n");
	}
	else
	{
		printf("\nSignature verification is disabled!\n");
	}
	enter_key();
}

void recover_android(int choice)
{
	print_logo();
	printf("Recovering Android partition.... Please wait....\n");
	printf("Formating Android System...\n");
	system("rm -rf /android/system");
	printf("Copying files...\n");
	system("cp -rp /backup/android/system /android/");
	printf("Done!\n");
	enter_key();
}


void flash_ota()
{
	system("rm -rf /root/ota/working/*");
	system("rm -rf /root/ota/temp/*");
	system("rm -rf /root/ota/certs/*");

	print_logo();
	if (access(ota_path, F_OK))
	{
		printf("OTA.zip file doesn't exists...\n");
		enter_key();
		return;
	}
	// copies the file to the root working directory...
	system("cp /home/seed/ota/ota.zip /root/ota/temp/ota.zip");

	// prepare the certificate for verification
	if (access("/android/system/etc/security/otacerts.zip", F_OK))
	{
		printf("/android/system/etc/security/otacerts.zip is missing...");
		enter_key();
		return;
	}
	system("cp /android/system/etc/security/otacerts.zip /root/ota/temp/otacerts.zip");
	system("unzip -d /root/ota/certs/ /root/ota/temp/otacerts.zip");

	if (signature_check)
	{
		if (!verify_file("/root/ota/temp/ota.zip") == VERIFY_SUCCESS)
		{
			printf("Signature verification failed.\n");
			enter_key();
			return;
		}
		else
		{
			printf("Signature verification success!\n");
		}
	}
	// unzips the ota update...
	// TODO: kinda dangerous to use system for this but it will have to do for now
	// to be rewritten
	system("unzip -d /root/ota/working/ /root/ota/temp/ota.zip");
	system("chmod -R u+x /root/ota/working/");
	system("/root/ota/working/META-INF/com/google/android/update-binary");
	printf("Done!\n");
	enter_key();
}


int main()
{
	char choice = 0;
	int exit = 0;

	print_logo();
	
	while (1)
	{
		print_logo();
		print_menu();
		choice = get_single_char();

		switch(choice)
		{
			case '1':
				flash_ota();
				break;
			case '2':
				disable_check();
				break;
			case '3':
				system("sudo -i -u seed");
				break;
			case '4':
				system("sudo -i -u root");
				break;
			case '5':
				system("reboot");
				break;
			default:
				printf("Please enter a 1, 2 or 3.\n");
				break;
		}
	}

	return 0;
}
