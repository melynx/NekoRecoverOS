#include <stdio.h>
#include <stdlib.h>

int signature_check = 1;

char get_single_char()
{
	char c = getchar();
	char d = c;
	while((d != '\n' && c != EOF)) d = getchar();
	return c;
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
				"2. Disable Signature check.\n"
				"3. Android Partial Revert(Only system folder).\n"
				"4. Enter Shell.\n"
				"\n"
				"Please enter an option :";

	print_logo();
	if (!signature_check)
	{
		printf("Signature verification is disabled!\n");
	}
	printf("%s", menu_string);
}

void disable_check()
{
	signature_check = 0;
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
	printf("Press enter to continue.");
	get_single_char();	
}

void flash_ota()
{
	print_logo();
	if (signature_check)
	{
		if (!verify_signature())
		{
			printf("Signature verification failed.\n");
			return;
		}
	}
	// unzips the ota update...
	// TODO: kinda dangerous to use system for this but it will have to do for now
	// to be rewritten
	system("rm -rf /root/ota/*");
	system("unzip -d /root/ota/");
	system("/root/ota/META-INF/com/google/android/update-binary");
	printf("Done!\n");
	printf("Press enter to continue.");
	get_single_char();	
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
				recover_android(choice);
				break;
			case '4':
				system("su -c /bin/bash seed");
				break;
			default:
				printf("Please enter a 1, 2 or 3.\n");
				break;
		}
	}

	return 0;
}
