from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import StrOutputParser

class GPTo1Chain:
    def __init__(self, model_name="o1-preview-2024-09-12"):
        load_dotenv()

        self.gpt_o1 = ChatOpenAI(
            model=model_name,
            max_tokens=32768,
            max_retries=2,
        )

        self.gpt_o1_chain = self.gpt_o1 | StrOutputParser()

    def invoke(self, prompt: str) -> str:
        llm_out = self.gpt_o1_chain.invoke(prompt)
        return llm_out

if __name__ == "__main__":
    gpto1_chain = GPTo1Chain()
    print(gpto1_chain.invoke("hello"))