/*
    Subject: Advanced OS(CS380L)
    Project 0: Wish Shell
    Author: Group22(Dohyun Kwon, Stefanus Adrian, Yunseok Kang)
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdbool.h>

void configurePath(char* newPath);
void showErrorMessage(void);
void startInteractiveMode(void);
int startBatchMode(char* batchArg);
void interpretAndExecute(char * commandBuffer);
void handleCommand(const char **commandArray);
void runCommand(char *iPath,char **commandArray);
char * buildPathString(const char** arrayComponents);

#define ERROR_MESSAGE "An error has occurred\n"
#define PATH_DEFAULT "/bin"
#define DEFAULT_CMD_BUF_SIZE 1024

char* globalPathString;

int main(int argc, char * argv[])
{
    char *startupMode = argv[1];
    configurePath(PATH_DEFAULT);

    // Determining the mode of operation based on argument count
    switch (argc) 
    {
        case 1:
            // Interactive mode
            startInteractiveMode();
            break;
        case 2:
            // Batch mode
            if (startBatchMode(startupMode) < 0) 
            {
                exit(EXIT_FAILURE);
            }
            break;
        default:
            // Incorrect usage, show error message
            showErrorMessage();
            exit(EXIT_FAILURE);
    }
    return EXIT_SUCCESS;
}

void configurePath(char* newPath)
{    
    bool isValidPath = newPath != NULL;

    if (false == isValidPath)
    {
        showErrorMessage();
        exit(EXIT_SUCCESS);
    }

    bool pathAlreadySet = globalPathString != NULL;
    if (true == pathAlreadySet) 
    {
        free(globalPathString);
    }

    globalPathString = strdup(newPath);

    // Ensure globalPathString is successfully updated
    if (NULL == globalPathString) 
    {
        showErrorMessage();
        exit(EXIT_FAILURE);
    }
}


void showErrorMessage(void)
{
    write(STDERR_FILENO,ERROR_MESSAGE,strlen(ERROR_MESSAGE));
}

void startInteractiveMode(void)
{	
    size_t bufferSize = 0;
    char *commandLine = NULL;

    // Check for interactive mode based on input redirection status
    bool isInteractive = (isatty(STDIN_FILENO) == 1);
    if (true == isInteractive)
    {
        printf("wish> ");
    }

    while (getline(&commandLine, &bufferSize, stdin) != -1)
    {
        interpretAndExecute(commandLine);
        printf("wish> ");
    }		

    // Free the allocated memory for commandLine
    if (commandLine != NULL)
    {
        free(commandLine);
    }
}


int startBatchMode(char* batchArg)
{
    // Check for null argument for safety
    if(NULL == batchArg) 
    {
        showErrorMessage();
        return -1;
    }

    FILE *batchFile = fopen(batchArg,"r");
    if (NULL == batchFile) 
    {
        showErrorMessage();
        return -1;
    }

    char *line = NULL;
    size_t lineSize = 0;
    ssize_t readSize;

    // Read and process each line of the file
    while (-1 != (readSize = getline(&line, &lineSize, batchFile))) 
    {
        interpretAndExecute(line);
    }

    if (NULL != line) 
    {
        free(line);  // Freeing the dynamically allocated memory
    }

    fclose(batchFile);  // Close the file after processing
    return 0;  // Indicate successful execution
}


void interpretAndExecute(char * commandBuffer)
{
    if (NULL == commandBuffer) 
    {
        showErrorMessage();
        return;
    }

    const char *commandArray[DEFAULT_CMD_BUF_SIZE];
    size_t commandArrayIndex = 0;

    const char *whitespace = " \t\r\n\v\f";
    const char *parallelDelimiter = "&";
    const char *redirectionDelimiter = ">";

    char *tokenParallel;
    char *tokenWhitespace;
    char *tokenRedirection;
    char *stateParallel;
    char *stateWhitespace;
    char *stateRedirection;

    for (tokenParallel = strtok_r(commandBuffer, parallelDelimiter, &stateParallel);
         NULL != tokenParallel;
         tokenParallel = strtok_r(NULL, parallelDelimiter, &stateParallel)) {

        for (tokenWhitespace = strtok_r(tokenParallel, whitespace, &stateWhitespace);
            NULL != tokenWhitespace;
             tokenWhitespace = strtok_r(NULL, whitespace, &stateWhitespace)) {

            if ((NULL != strstr(tokenWhitespace, ">")) && (0 != strcmp(tokenWhitespace, ">"))) 
            {
                tokenRedirection = strtok_r(tokenWhitespace, redirectionDelimiter, &stateRedirection);
                while (NULL != tokenRedirection) 
                {
                    commandArray[commandArrayIndex++] = strdup(tokenRedirection);
                    tokenRedirection = strtok_r(NULL, redirectionDelimiter, &stateRedirection);
                    if (NULL != tokenRedirection) 
                    {
                        commandArray[commandArrayIndex++] = strdup(">");
                    }
                }
                break;
            }
            commandArray[commandArrayIndex++] = strdup(tokenWhitespace);
        }

        commandArray[commandArrayIndex] = NULL;
        handleCommand(commandArray);

        for (size_t i = 0; i < commandArrayIndex; i++) {
            free((void *)commandArray[i]);
        }
        commandArrayIndex = 0;
    }

    // Wait for all child processes
    while (wait(NULL) > 0);
}

void handleCommand(const char **commandArray)
{
    int commandFound = -1;
    char *finalCommandPath = NULL;
    char *pathTokens = strdup(globalPathString);

    char *token;
    char *savePtr;
    const char delimiters[] = " \t\r\n\v\f";   // Whitespace delimiters

    if (NULL == commandArray[0]) 
    {
        return;
    }

    // Handling built-in commands
    if (0 == strcmp("exit", commandArray[0])) 
    {
        if (commandArray[1] != NULL) 
        {
            showErrorMessage();
            return;
        }
        exit(EXIT_SUCCESS);
    } 
    else if (0 == strcmp("cd", commandArray[0])) 
    {
        if ((NULL != commandArray[2]) || (-1 == chdir(commandArray[1]))) 
        {
            showErrorMessage();
        }
        return;
    } 
    else if (0 == strcmp("path", commandArray[0])) 
    {
        char *newPath = buildPathString(commandArray);
        if (NULL != newPath) 
        {
            configurePath(newPath);
        }
        return;
    }

    // Tokenizing path for spaces
    for (token = strtok_r(pathTokens, delimiters, &savePtr); token != NULL; token = strtok_r(NULL, delimiters, &savePtr)) 
    {
        finalCommandPath = (char *) malloc((strlen(token) + strlen(commandArray[0]) + 2) * sizeof(char)); 
        strcpy(finalCommandPath, token);
        strcat(finalCommandPath, "/");
        strcat(finalCommandPath, commandArray[0]);

        commandFound = access(finalCommandPath, X_OK);

        if (0 == commandFound) 
        {
            runCommand(finalCommandPath, (char**)commandArray);
            break;
        }
    }

    if (-1 == commandFound) 
    {
        showErrorMessage();
    }

    free(pathTokens);
    free(finalCommandPath);
}


void runCommand(char *iPath, char **commandArray)
{
    pid_t childPid = fork();

    // Handle fork failure
    if (0 > childPid) 
    {
        showErrorMessage();
        exit(EXIT_FAILURE);
    }

    // Child process logic
    if (0 == childPid) 
    {
        int redirectCount = 0;
        int outputFileIndex = 0;

        // Checking for output redirection
        for (int i = 0; commandArray[i] != NULL; i++) 
        {
            if (0 == strcmp(commandArray[i], ">")) 
            {
                redirectCount++;
                outputFileIndex = i + 1;

                // Validating redirection syntax
                if ((NULL == commandArray[outputFileIndex]) || (NULL != commandArray[outputFileIndex + 1]))
                {
                    showErrorMessage();
                    return;
                }
            }
        }

        // Handling more than one redirection
        if (1 < redirectCount) 
        {
            showErrorMessage();
            return;
        }

        // Setting up redirection if needed
        if (1 == redirectCount) 
        {
            char *outputFilePath = strdup(commandArray[outputFileIndex]);
            close(STDOUT_FILENO);
            open(outputFilePath, O_CREAT | O_WRONLY | O_TRUNC, S_IRWXU);
            commandArray[outputFileIndex - 1] = NULL;
            commandArray[outputFileIndex] = NULL;
            free(outputFilePath);
        }

        // Execute the command
        if (-1 == execv(iPath, commandArray)) 
        {
            showErrorMessage();
            return;
        }
    }
}

char * buildPathString(const char** arrayComponents)
{
    int index = 1;  // Start from index 1 as per original logic
    int totalLength = 0;  // Total length for the concatenated string

    // Calculate total length and count number of components
    while (NULL != arrayComponents[index] ) 
    {
        totalLength += strlen(arrayComponents[index]) + 1;  // Add 1 for space
        index++;
    }

    // Allocate memory for the concatenated string
    char *concatenatedResult = calloc(totalLength, sizeof(char));
    if (NULL == concatenatedResult) 
    {
        return NULL;  // Return NULL if memory allocation fails
    }

    // Concatenate the components
    for (int i = 1; i < index; i++) 
    {
        strcat(concatenatedResult, arrayComponents[i]);
        strcat(concatenatedResult, " ");
    }
    return concatenatedResult;
}