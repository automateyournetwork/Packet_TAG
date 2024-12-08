import os
import pandas as pd
import subprocess
import streamlit as st
from openai import OpenAI
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Streamlit
st.set_page_config(page_title="Packet TAG", page_icon="📄")

# Load OpenAI API key
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def query_openai(prompt):
    """
    Query the OpenAI GPT model with a prompt using the updated client.
    """
    try:
        chat_completion = client.chat.completions.create(
            model="gpt-4",  # Specify the model
            messages=[{"role": "user", "content": prompt}]
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        raise RuntimeError(f"Error querying OpenAI API: {e}")

# Function to convert .pcap to CSV using a subset of fields
def pcap_to_csv_with_subset(pcap_path, csv_path):
    fields = [
        "frame.number", "frame.time", "frame.len",
        "ip.src", "ip.dst", "ip.proto",
        "tcp.srcport", "tcp.dstport",
        "udp.srcport", "udp.dstport",
        "eth.src", "eth.dst",
        "dns.qry.name", "dns.a"
    ]
    field_options = " ".join([f"-e {field}" for field in fields])
    command = f'tshark -r "{pcap_path}" -T fields {field_options} -E header=y -E separator=, > "{csv_path}"'
    result = subprocess.run(command, shell=True)
    if result.returncode != 0:
        raise Exception(f"Error converting PCAP to CSV: {result.stderr}")

def load_csv_as_dataframe(csv_path):
    return pd.read_csv(csv_path)

def generate_query_prompt(schema, query):
    """
    Generate a prompt to translate a user question into a structured query.
    """
    return f"""
    The table schema is as follows:
    {schema}

    The table is stored in a variable named `df`.

    Convert the following question into a Pandas DataFrame query:
    Question: {query}

    Provide the query code only. Do not include explanations.
    """

def upload_and_process_pcap():
    MAX_FILE_SIZE_MB = 5
    uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

    if uploaded_file:
        if uploaded_file.size > MAX_FILE_SIZE_MB * 1024 * 1024:
            st.error(f"The file exceeds the maximum size of {MAX_FILE_SIZE_MB} MB.")
            return

        temp_dir = "temp"
        os.makedirs(temp_dir, exist_ok=True)

        pcap_path = os.path.join(temp_dir, uploaded_file.name)
        csv_path = pcap_path.replace(".pcap", ".csv")

        with open(pcap_path, "wb") as f:
            f.write(uploaded_file.getvalue())

        try:
            pcap_to_csv_with_subset(pcap_path, csv_path)
            st.success("PCAP file successfully processed and converted to CSV.")
            df = load_csv_as_dataframe(csv_path)
            st.session_state['pcap_dataframe'] = df

        except Exception as e:
            st.error(f"Error processing PCAP: {e}")
        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)
            if os.path.exists(csv_path):
                os.remove(csv_path)

def tag_query_interface():
    """
    Provide an interface to query the processed PCAP table using OpenAI LLM and generate conversational responses.
    """
    if 'pcap_dataframe' not in st.session_state:
        st.error("Please upload and process a PCAP file first.")
        return

    df = st.session_state['pcap_dataframe']
    user_query = st.text_input("Ask a question about the PCAP data:")

    if st.button("Send Query"):
        if not user_query.strip():
            st.warning("Please enter a question.")
            return

        # Generate schema and prompt for query generation
        schema = "\n".join(f"- {col}" for col in df.columns)
        prompt = generate_query_prompt(schema, user_query)

        try:
            # Query OpenAI to generate DataFrame query
            with st.spinner("Generating DataFrame query..."):
                query_code = query_openai(prompt)
            st.markdown(f"### Generated Query:\n```python\n{query_code}\n```")

            # Execute the query on the DataFrame
            result = eval(query_code, {'df': df})
            st.markdown("### Query Results:")
            st.dataframe(result)

            # Convert results to markdown for LLM
            result_preview = result.to_markdown(index=False)
            conversational_prompt = f"""
            Here are the query results based on the user's question:

            {result_preview}

            Provide a concise and conversational summary of the data for the user.
            """
            with st.spinner("Generating conversational response..."):
                conversational_response = query_openai(conversational_prompt)
            
            st.markdown("### Conversational Response:")
            st.write(conversational_response)

        except Exception as e:
            st.error(f"Error: {e}")

# Main Application Logic
def main():
    st.title("Packet TAG: Table-Augmented Generation for PCAP Analysis")
    st.markdown("---")
    st.subheader("Step 1: Upload and Convert PCAP")
    upload_and_process_pcap()
    st.markdown("---")
    st.subheader("Step 2: Query the Table with LLM Assistance")
    tag_query_interface()

if __name__ == "__main__":
    main()
