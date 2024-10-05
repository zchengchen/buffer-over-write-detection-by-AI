# GPT for Out-of-bounds write
from openai import OpenAI
from os import getenv

client = OpenAI(
  api_key=getenv("OPENAI_API_KEY"),
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": "Tell me about the solar system."}
    ]
)

print(response.choices[0].message.content)