# Packet TAG: Table-Augmented Generation for PCAP Analysis

Packet TAG is a Streamlit-based application designed for analyzing PCAP files with the help of OpenAI's GPT-4. It provides an intuitive interface to upload PCAP files, convert them into tabular data, and query the data conversationally using natural language. This application utilizes Docker for deployment and requires minimal setup.

## Features

Upload PCAP Files: Convert packet capture files into structured CSV format using tshark.

OpenAI GPT-4 Integration: Ask questions about the data, and the AI generates accurate responses by querying the underlying table.

Conversational Interface: Includes natural language interaction for intuitive data analysis.

Dockerized Deployment: Simple deployment with docker-compose.

### Prerequisites

Install Docker: Ensure Docker and Docker Compose are installed on your system.

OpenAI API Key: Obtain an API key from OpenAI.

### Setup Instructions

Clone the Repository
```bash
git clone <repository-url>
cd <repository-name>
```

Update the Environment File

Locate the .env file in the project directory.

Add your OpenAI API key:

```bash
OPENAI_API_KEY=your_openai_api_key_here
```

### Build and Run the Docker Container

Build and start the container using Docker Compose:

```bash
docker-compose up --build
```

Open your browser and visit:

http://localhost:8501

### Usage

Step 1: Upload a PCAP File

Navigate to the "Step 1" section.

Upload a PCAP file (.pcap or .pcapng format).

The application converts the file into a CSV table with selected fields for analysis.

Step 2: Query the Table with Natural Language

Enter a question in the input box (e.g., "What are the source and destination IP addresses?").

The AI processes the question, generates a query, and retrieves the relevant data.

Receive both a structured table response and a conversational summary.

### Example Questions

"What is the source and destination IP?"

"Show me the top 10 DNS queries."

"Which protocols are used in the packet capture?"

### File Details

PCAP Conversion

Uses tshark to extract key fields such as ip.src, ip.dst, tcp.srcport, and dns.qry.name.

Outputs the data as a structured CSV file.

### AI-Powered Queries

GPT-4 generates Pandas DataFrame queries to extract specific information from the table.

Provides conversational summaries of the results.

### Key Technologies

Streamlit: Frontend for user interaction.

OpenAI GPT-4: AI model for natural language understanding.

Pandas: For handling tabular data.

tshark: For converting PCAP files into CSV format.

Docker: For containerized deployment.

### Troubleshooting

Common Issues

Error: tshark not found:

Ensure tshark is installed in the Docker container. It should already be part of the provided Docker image.

OpenAI API Errors:

Verify your API key is correct and has sufficient credits.

Check for rate limits if querying frequently.

PCAP Conversion Errors:

Ensure the uploaded file is a valid .pcap or .pcapng file.

### Contributing

Contributions are welcome! Feel free to fork the repository, make improvements, and submit a pull request.

### License

This project is licensed under the MIT License. See the LICENSE file for details.

### Contact

For issues or feedback, please open an issue in the repository or contact the project maintainer.

Enjoy analyzing your network data with the power of AI! 🎉






