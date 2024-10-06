# GPT for Out-of-bounds write
from openai import OpenAI
from os import getenv
from github import Github
import json

####################################################################################################
# To fetch all history commits of challenge-004-nginx-source.                                      #
# And store the commit infomation in commits.josn                                                  #
####################################################################################################
# access_token = getenv("GITHUB_TOKEN")
# g = Github(access_token)

# repo_name = "aixcc-public/challenge-004-nginx-source"
# repo = g.get_repo(repo_name)

# commits = repo.get_commits()
# commits_info = []

# for commit in commits:
#     # print(f"Commit SHA: {commit.sha}")
#     # print(f"Commit {commit.commit.message}")
#     commit_detail = repo.get_commit(commit.sha)
#     info = {"commit_sha": commit.sha, "commit_index": commit.commit.message, "commit_diff": ""}
#     for file in commit_detail.files:
#         # print(f"Diff:\n{file.patch}\n")
#         info["commit_diff"] += f"Diff:\n{file.patch}\n"
#     commits_info.append(info)

# with open("commits.json", "w") as f:
#   print(json.dumps(commits_info, ensure_ascii=False), file=f)

commits_history = {}
with open("commits.json", "r", encoding="utf-8") as file:
    commits_history = json.load(file)

client = OpenAI(
  api_key=getenv("OPENAI_API_KEY"),
)

def send_message(message, conversation_history):
    response = openai.ChatCompletion.create(
        model="gpt-4o",
        messages=conversation_history + [{"role": "user", "content": message}]
    )
    return response['choices'][0]['message']['content']

gpt_context = """
You are an assistant to help software security expert to find vulnerabilities in history commits of Github repo. 
You need to find vulnerbility concerning Out-of-bounds write and try your best to patch the code. The followings 
are some classic examples of Out-of-bounds write to help you understand its principles.

Out-of-bounds write
  Brief description: The product writes data past the end, or before the beginning, of the intended buffer.
  (1) Example 1:
    The following code attempts to save four different identification numbers into an array.
    int id_sequence[3];
    /* Populate the id array. */
    id_sequence[0] = 123;
    id_sequence[1] = 234;
    id_sequence[2] = 345;
    id_sequence[3] = 456;
  Since the array is only allocated to hold three elements, the valid indices are 0 to 2; so, the assignment to 
  id_sequence[3] is out of bounds.
  (2) Example 2:
    In the following code, it is possible to request that memcpy move a much larger segment of memory than assumed:
    int returnChunkSize(void *) {

      /* if chunk info is valid, return the size of usable memory,

      * else, return -1 to indicate an error

      */
      ...
      }
      int main() {
      ...
      memcpy(destBuf, srcBuf, (returnChunkSize(destBuf)-1));
      ...
    }
  If returnChunkSize() happens to encounter an error it will return -1. Notice that the return value is not checked 
  before the memcpy operation (CWE-252), so -1 can be passed as the size argument to memcpy() (CWE-805). Because memcpy() 
  assumes that the value is unsigned, it will be interpreted as MAXINT-1 (CWE-195), and therefore will copy far more memory 
  than is likely available to the destination buffer (CWE-787, CWE-788).
  (3) Example 3:
    In the following code, it is possible to request that memcpy move a much larger segment of memory than assumed:
    void host_lookup(char *user_supplied_addr){
      struct hostent *hp;
      in_addr_t *addr;
      char hostname[64];
      in_addr_t inet_addr(const char *cp);

      /*routine that ensures user_supplied_addr is in the right format for conversion */

      validate_addr_form(user_supplied_addr);
      addr = inet_addr(user_supplied_addr);
      hp = gethostbyaddr( addr, sizeof(struct in_addr), AF_INET);
      strcpy(hostname, hp->h_name);
    }
  This function allocates a buffer of 64 bytes to store the hostname. However, there is no guarantee that the hostname 
  will not be larger than 64 bytes. If an attacker specifies an address which resolves to a very large hostname, then 
  the function may overwrite sensitive data or even relinquish control flow to the attacker.
  Note that this example also contains an unchecked return value (CWE-252) that can lead to a NULL pointer dereference (CWE-476).
  (4) Example 4:
    This code applies an encoding procedure to an input string and stores it into a buffer.
    char * copy_input(char *user_supplied_string){
      int i, dst_index;
      char *dst_buf = (char*)malloc(4*sizeof(char) * MAX_SIZE);
      if ( MAX_SIZE <= strlen(user_supplied_string) ){
        die("user string too long, die evil hacker!");
      }
        dst_index = 0;
      for ( i = 0; i < strlen(user_supplied_string); i++ ){
        if( '&' == user_supplied_string[i] ){
          dst_buf[dst_index++] = '&';
          dst_buf[dst_index++] = 'a';
          dst_buf[dst_index++] = 'm';
          dst_buf[dst_index++] = 'p';
          dst_buf[dst_index++] = ';';
        }
        else if ('<' == user_supplied_string[i] ){

        /* encode to &lt; */
      }
        else dst_buf[dst_index++] = user_supplied_string[i];
      }
      return dst_buf;
    }
  The programmer attempts to encode the ampersand character in the user-controlled string. However, the length of the string is validated 
  before the encoding procedure is applied. Furthermore, the programmer assumes encoding expansion will only expand a given character by a 
  factor of 4, while the encoding of the ampersand expands by 5. As a result, when the encoding procedure expands the string it is possible 
  to overflow the destination buffer if the attacker provides a string of many ampersands.
  (5) Example 5:
    In the following C/C++ code, a utility function is used to trim trailing whitespace from a character string. The function copies the input 
    string to a local character string and uses a while statement to remove the trailing whitespace by moving backward through the string and 
    overwriting whitespace with a NUL character.
    char* trimTrailingWhitespace(char *strMessage, int length) {
      char *retMessage;
      char *message = malloc(sizeof(char)*(length+1));

      // copy input string to a temporary string
      char message[length+1];
      int index;
      for (index = 0; index < length; index++) {
        message[index] = strMessage[index];
      }
      message[index] = '\0';

      // trim trailing whitespace
      int len = index-1;
      while (isspace(message[len])) {
        message[len] = '\0';
        len--;
      }

      // return string without trailing whitespace
      retMessage = message;
      return retMessage;
    }
  However, this function can cause a buffer underwrite if the input character string contains all whitespace. On some systems the while statement 
  will move backwards past the beginning of a character string and will call the isspace() function on an address outside of the bounds of the local buffer.
  (6) Example 6
    The following code allocates memory for a maximum number of widgets. It then gets a user-specified number of widgets, making sure that the user does not 
    request too many. It then initializes the elements of the array using InitializeWidget(). Because the number of widgets can vary for each request, the code 
    inserts a NULL pointer to signify the location of the last widget.
    int i;
    unsigned int numWidgets;
    Widget **WidgetList;

    numWidgets = GetUntrustedSizeValue();
    if ((numWidgets == 0) || (numWidgets > MAX_NUM_WIDGETS)) {
      ExitError("Incorrect number of widgets requested!");
    }
      WidgetList = (Widget **)malloc(numWidgets * sizeof(Widget *));
      printf("WidgetList ptr=%p\n", WidgetList);
    for(i=0; i<numWidgets; i++) {
      WidgetList[i] = InitializeWidget();
    }
    WidgetList[numWidgets] = NULL;
    showWidgets(WidgetList);
  However, this code contains an off-by-one calculation error (CWE-193). It allocates exactly enough space to contain the specified number of widgets, but it 
  does not include the space for the NULL pointer. As a result, the allocated buffer is smaller than it is supposed to be (CWE-131). So if the user ever requests 
  MAX_NUM_WIDGETS, there is an out-of-bounds write (CWE-787) when the NULL is assigned. Depending on the environment and compilation settings, this could cause 
  memory corruption.
  (7) Example 7
    The following is an example of code that may result in a buffer underwrite. This code is attempting to replace the substring "Replace Me" in destBuf with the 
    string stored in srcBuf. It does so by using the function strstr(), which returns a pointer to the found substring in destBuf. Using pointer arithmetic, the 
    starting index of the substring is found.
    int main() {
      ...
      char *result = strstr(destBuf, "Replace Me");
      int idx = result - destBuf;
      strcpy(&destBuf[idx], srcBuf);
      ...
    }
  In the case where the substring is not found in destBuf, strstr() will return NULL, causing the pointer arithmetic to be undefined, potentially setting the value 
  of idx to a negative number. If idx is negative, this will result in a buffer underwrite of destBuf.

  What should you do to check whether a function has out-of-bounds vulnerability?
  1. You should find the newly added entire functions and only need to analyze these functions, and please ignore other changes.
  2. Analyse these function separately line by line.

  Some key points for finding vulnerabilities:
  1. Some safe functions
    Functions which are similar to strncpy, snprintf and strncat could keep the software safe.
  2. Buffer with fixed size
    Buffer with fixed size could keep the software safe.

There may be other types of vulnerabilities here as well in history commits, as follows:
1. Heap-based Buffer Overflow
  Brief description: A heap overflow condition is a buffer overflow, where the buffer that can be overwritten is allocated in the heap portion of memory, generally 
  meaning that the buffer was allocated using a routine such as malloc().
2. Null Pointer Dereference
  Brief description: The product dereferences a pointer that it expects to be valid but is NULL.
3. Use-After-Free
  Brief description: The product reuses or references memory after it has been freed. At some point afterward, the memory may be allocated again and saved in another 
  pointer, while the original pointer references a location somewhere within the new allocation. Any operations using the original pointer are no longer valid because 
  the memory "belongs" to the code that operates on the new pointer.
4. Double Free
  Brief description: The product calls free() twice on the same memory address, potentially leading to modification of unexpected memory locations.
5. Out of Bounds Read
  Brief description: The product reads data past the end, or before the beginning, of the intended buffer.
You DO NOT need to care these five typical vulnerabilities. You ONLY need to search for Out-of-bounds write vulnerabilit.
"""

gpt_ask_header = """
Forget the previous commit analysis result. You only need to analyze the newly added entire functions, and please ignore other changes (DO NOT input information of these changes). 
You should firstly find newly added entire functions, and ignore remainder. If there is not newly added function, just return "FALSE". You should analyze each new function separately 
line by line to find whether there is possibility of out-of-bounds write under assumption that a certain user is extremely malicious. If there is a suspicious function, please return 
the information in format "TRUE [func_a] [func_b]" in the final line without extra character. Attention: you do not need definitive proof of out-of-bounds write. 
"""

# response = client.chat.completions.create(
#     model="gpt-4o",
#     messages=[
#         {"role": "system", "content": gpt_context},
#     ]
# )

def send_message(message):
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[
          {"role": "system", "content": gpt_context},
          {"role": "user", "content": message}
        ]
    )
    return response.choices[0].message.content

with open("result.txt", "w") as f:
  print("GPT-4o analysis result", file=f)

for commit in commits_history:
  commit_index = commit["commit_index"]
  if commit_index == "Initial Commit":
    break
  commit_diff = commit["commit_diff"]
  gpt_ask_content = gpt_ask_header + "\n\n" + commit_diff
  with open("result.txt", "a") as f:
    print(commit_index, file=f)
    print(send_message(gpt_ask_content), file=f)
    print("\n", file=f)