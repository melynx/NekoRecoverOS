#include <stdio.h>
#include <stdlib.h>

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

	//printf("%s", text);
}

void print_menu()
{
	char *menu_string =     "1. Flash OTA.zip.\n"
				"2. Full Revert Android.\n"
				"3. Partial Revert Android.\n"
				"4. Enter Shell.\n"
				"\n"
				"Please enter an option :";

	print_logo();
	printf("%s", menu_string);
}

void recover_android(int choice)
{
	print_logo();
	printf("Recovering Android partition.... Please wait....\n");
	if (choice == '2')
	{
		printf("Formating Android...\n");
		system("rm -rf /android/*");
	}
	printf("Copying files...\n");
	system("cp -rp /backup/android/* /android/");
	printf("Done!\n");
	printf("Press enter to continue.");
	get_single_char();	
}

void flash_ota()
{
	print_logo();
	system("/tmp/ota/META-INF/com/google/android/update-binary");
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
			case '3':
				recover_android(choice);
				break;
			case '4':
				system("/bin/bash");	
				break;
			default:
				printf("Please enter a 1, 2 or 3.\n");
				break;
		}
	}

	return 0;
}
