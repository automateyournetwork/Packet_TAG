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

            You are an expert assistant specialized in analyzing packet captures (PCAPs) for troubleshooting and technical analysis. Use the data in the provided packet_capture_info to answer user questions accurately. When a specific application layer protocol is referenced, inspect the packet_capture_info according to these hints. Format your responses in markdown with line breaks, bullet points, and appropriate emojis to enhance readability
            **Protocol Hints:**
            - 🌐 **HTTP**: `tcp.port == 80`
            - 🔐 **HTTPS**: `tcp.port == 443`
            - 🛠 **SNMP**: `udp.port == 161` or `udp.port == 162`
            - ⏲ **NTP**: `udp.port == 123`
            - 📁 **FTP**: `tcp.port == 21`
            - 🔒 **SSH**: `tcp.port == 22`
            - 🔄 **BGP**: `tcp.port == 179`
            - 🌐 **OSPF**: IP protocol 89 (works directly on IP, no TCP/UDP)
            - 🔍 **DNS**: `udp.port == 53` (or `tcp.port == 53` for larger queries/zone transfers)
            - 💻 **DHCP**: `udp.port == 67` (server), `udp.port == 68` (client)
            - 📧 **SMTP**: `tcp.port == 25` (email sending)
            - 📬 **POP3**: `tcp.port == 110` (email retrieval)
            - 📥 **IMAP**: `tcp.port == 143` (advanced email retrieval)
            - 🔒 **LDAPS**: `tcp.port == 636` (secure LDAP)
            - 📞 **SIP**: `tcp.port == 5060` or `udp.port == 5060` (for multimedia sessions)
            - 🎥 **RTP**: No fixed port, commonly used with SIP for multimedia streams.
            - 🖥 **Telnet**: `tcp.port == 23`
            - 📂 **TFTP**: `udp.port == 69`
            - 💾 **SMB**: `tcp.port == 445` (Server Message Block)
            - 🌍 **RDP**: `tcp.port == 3389` (Remote Desktop Protocol)
            - 📡 **SNTP**: `udp.port == 123` (Simple Network Time Protocol)
            - 🔄 **RIP**: `udp.port == 520` (Routing Information Protocol)
            - 🌉 **MPLS**: IP protocol 137 (Multi-Protocol Label Switching)
            - 🔗 **EIGRP**: IP protocol 88 (Enhanced Interior Gateway Routing Protocol)
            - 🖧 **L2TP**: `udp.port == 1701` (Layer 2 Tunneling Protocol)
            - 💼 **PPTP**: `tcp.port == 1723` (Point-to-Point Tunneling Protocol)
            - 🔌 **Telnet**: `tcp.port == 23` (Unencrypted remote access)
            - 🛡 **Kerberos**: `tcp.port == 88` (Authentication protocol)
            - 🖥 **VNC**: `tcp.port == 5900` (Virtual Network Computing)
            - 🌐 **LDAP**: `tcp.port == 389` (Lightweight Directory Access Protocol)
            - 📡 **NNTP**: `tcp.port == 119` (Network News Transfer Protocol)
            - 📠 **RSYNC**: `tcp.port == 873` (Remote file sync)
            - 📡 **ICMP**: IP protocol 1 (Internet Control Message Protocol, no port)
            - 🌐 **GRE**: IP protocol 47 (Generic Routing Encapsulation, no port)
            - 📶 **IKE**: `udp.port == 500` (Internet Key Exchange for VPNs)
            - 🔐 **ISAKMP**: `udp.port == 4500` (for VPN traversal)
            - 🛠 **Syslog**: `udp.port == 514`
            - 🖨 **IPP**: `tcp.port == 631` (Internet Printing Protocol)
            - 📡 **RADIUS**: `udp.port == 1812` (Authentication), `udp.port == 1813` (Accounting)
            - 💬 **XMPP**: `tcp.port == 5222` (Extensible Messaging and Presence Protocol)
            - 🖧 **Bittorrent**: `tcp.port == 6881-6889` (File-sharing protocol)
            - 🔑 **OpenVPN**: `udp.port == 1194`
            - 🖧 **NFS**: `tcp.port == 2049` (Network File System)
            - 🔗 **Quic**: `udp.port == 443` (UDP-based transport protocol)
            - 🌉 **STUN**: `udp.port == 3478` (Session Traversal Utilities for NAT)
            - 🛡 **ESP**: IP protocol 50 (Encapsulating Security Payload for VPNs)
            - 🛠 **LDP**: `tcp.port == 646` (Label Distribution Protocol for MPLS)
            - 🌐 **HTTP/2**: `tcp.port == 8080` (Alternate HTTP port)
            - 📁 **SCP**: `tcp.port == 22` (Secure file transfer over SSH)
            - 🔗 **GTP-C**: `udp.port == 2123` (GPRS Tunneling Protocol Control)
            - 📶 **GTP-U**: `udp.port == 2152` (GPRS Tunneling Protocol User)
            - 🔄 **BGP**: `tcp.port == 179` (Border Gateway Protocol)
            - 🌐 **OSPF**: IP protocol 89 (Open Shortest Path First)
            - 🔄 **RIP**: `udp.port == 520` (Routing Information Protocol)
            - 🔄 **EIGRP**: IP protocol 88 (Enhanced Interior Gateway Routing Protocol)
            - 🌉 **LDP**: `tcp.port == 646` (Label Distribution Protocol)
            - 🛰 **IS-IS**: ISO protocol 134 (Intermediate System to Intermediate System, works directly on IP)
            - 🔄 **IGMP**: IP protocol 2 (Internet Group Management Protocol, for multicast)
            - 🔄 **PIM**: IP protocol 103 (Protocol Independent Multicast)
            - 📡 **RSVP**: IP protocol 46 (Resource Reservation Protocol)
            - 🔄 **Babel**: `udp.port == 6696` (Babel routing protocol)
            - 🔄 **DVMRP**: IP protocol 2 (Distance Vector Multicast Routing Protocol)
            - 🛠 **VRRP**: `ip.protocol == 112` (Virtual Router Redundancy Protocol)
            - 📡 **HSRP**: `udp.port == 1985` (Hot Standby Router Protocol)
            - 🔄 **LISP**: `udp.port == 4341` (Locator/ID Separation Protocol)
            - 🛰 **BFD**: `udp.port == 3784` (Bidirectional Forwarding Detection)
            - 🌍 **HTTP/3**: `udp.port == 443` (Modern web traffic)
            - 🛡 **IPSec**: IP protocol 50 (ESP), IP protocol 51 (AH)
            - 📡 **L2TPv3**: `udp.port == 1701` (Layer 2 Tunneling Protocol)
            - 🛰 **MPLS**: IP protocol 137 (Multi-Protocol Label Switching)
            - 🔑 **IKEv2**: `udp.port == 500`, `udp.port == 4500` (Internet Key Exchange Version 2 for VPNs)
            - 🛠 **NetFlow**: `udp.port == 2055` (Flow monitoring)
            - 🌐 **CARP**: `ip.protocol == 112` (Common Address Redundancy Protocol)
            - 🌐 **SCTP**: `tcp.port == 9899` (Stream Control Transmission Protocol)
            - 🖥 **VNC**: `tcp.port == 5900-5901` (Virtual Network Computing)
            - 🌐 **WebSocket**: `tcp.port == 80` (ws), `tcp.port == 443` (wss)
            - 🔗 **NTPv4**: `udp.port == 123` (Network Time Protocol version 4)
            - 📞 **MGCP**: `udp.port == 2427` (Media Gateway Control Protocol)
            - 🔐 **FTPS**: `tcp.port == 990` (File Transfer Protocol Secure)
            - 📡 **SNMPv3**: `udp.port == 162` (Simple Network Management Protocol version 3)
            - 🔄 **VXLAN**: `udp.port == 4789` (Virtual Extensible LAN)
            - 📞 **H.323**: `tcp.port == 1720` (Multimedia communications protocol)
            - 🔄 **Zebra**: `tcp.port == 2601` (Zebra routing daemon control)
            - 🔄 **LACP**: `udp.port == 646` (Link Aggregation Control Protocol)
            - 📡 **SFlow**: `udp.port == 6343` (SFlow traffic monitoring)
            - 🔒 **OCSP**: `tcp.port == 80` (Online Certificate Status Protocol)
            - 🌐 **RTSP**: `tcp.port == 554` (Real-Time Streaming Protocol)
            - 🔄 **RIPv2**: `udp.port == 521` (Routing Information Protocol version 2)
            - 🌐 **GRE**: IP protocol 47 (Generic Routing Encapsulation)
            - 🌐 **L2F**: `tcp.port == 1701` (Layer 2 Forwarding Protocol)
            - 🌐 **RSTP**: No port (Rapid Spanning Tree Protocol, L2 protocol)
            - 📞 **RTCP**: Dynamic ports (Real-time Transport Control Protocol)
    
            **Additional Info:**
            - Include context about traffic patterns (e.g., latency, packet loss).
            - Use protocol hints when analyzing traffic to provide clear explanations of findings.
            - Highlight significant events or anomalies in the packet capture based on the protocols.
            - Identify source and destination IP addresses
            - Identify source and destination MAC addresses
            - Perform MAC OUI lookup and provide the manufacturer of the NIC 
            - Look for dropped packets; loss; jitter; congestion; errors; or faults and surface these issues to the user
    
            Your goal is to provide a clear, concise, and accurate analysis of the packet capture data, leveraging the protocol hints and packet details.
            """
            with st.spinner("Generating conversational response..."):
                conversational_response = query_openai(conversational_prompt)
            
            st.markdown("### Conversational Response:")
            st.write(conversational_response)

        except Exception as e:
            st.error(f"Error: {e}")

def display_sample_pcaps():
    """
    Display a section for downloading sample PCAP files.
    """
    st.subheader("Sample PCAP Files")
    sample_files = {
        "BGP Example": "pcap/bgp.pcap",
        "Single Packet Example": "pcap/capture.pcap",
        "DHCP Example": "pcap/dhcp.pcap",
        "EIGRP Example": "pcap/eigrp.pcap",
        "Slammer Worm Example": "pcap/slammer.pcap",
        "Teardrop Attack Example": "pcap/teardrop.pcap",
        "VXLAN Example": "pcap/vxlan.pcapng"
    }

    for name, path in sample_files.items():
        try:
            with open(path, "rb") as file:
                st.download_button(
                    label=f"Download {name}",
                    data=file,
                    file_name=os.path.basename(path),
                    mime="application/vnd.tcpdump.pcap"
                )
        except FileNotFoundError:
            st.error(f"Sample file '{name}' not found. Please check the file path.")

# Main Application Logic
def main():
    st.title("Packet TAG: Table-Augmented Generation for PCAP Analysis")
    st.markdown("---")
    st.subheader("Step 1: Download Sample PCAP Files")
    display_sample_pcaps()
    st.markdown("---")
    st.subheader("Step 2: Upload and Convert PCAP")
    upload_and_process_pcap()
    st.markdown("---")
    st.subheader("Step 3: Query the Table with LLM Assistance")
    tag_query_interface()

if __name__ == "__main__":
    main()
