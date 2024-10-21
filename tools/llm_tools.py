from openai import OpenAI
from os import getenv

client = OpenAI(
  api_key=getenv("OPENAI_API_KEY"),
)

# def send_message(message):
#   response = client.chat.completions.create(
#       model="gpt-4o",
#       messages=[
#         {"role": "user", "content": message}
#       ]
#   )
#   return response.choices[0].message.content

# def send_message(message, history):
#   messages = []
#   if history != None and len(history) != 0:
#     for i in range(0, len(history)):
#       if i % 2 == 1:
#         messages.append({"role": "user", "content": history[i]})
#       else:
#         messages.append({"role": "assistant", "content": history[i]})
#   messages.append({"role": "user", "content": message})
#   response = client.chat.completions.create(
#       model="gpt-4o",
#       messages=messages
#   )
#   return response.choices[0].message.content

# gets API Key from environment variable OPENAI_API_KEY
client = OpenAI(
  base_url="https://openrouter.ai/api/v1",
  api_key=getenv("OPENROUTER_API_KEY"),
)

def send_message(message, history):
    completion = client.chat.completions.create(
    model="openai/o1-preview-2024-09-12",
    messages=[
        {
        "role": "user",
        "content": message
        }
    ]
    )
    return completion.choices[0].message.content