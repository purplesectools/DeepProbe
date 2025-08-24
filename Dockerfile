# Use an official Python runtime as a parent image, switching to a more current Debian release
FROM python:3.11-slim-bullseye

# Set the working directory in the container
WORKDIR /app

# Install system dependencies needed for Volatility3 and git
# Volatility3 might need specific libraries depending on its plugins
# Add a retry mechanism for apt-get update to handle transient network issues
RUN apt-get update || (sleep 5 && apt-get update) && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    libcapstone-dev \
    # Add other system dependencies if Volatility3 plugins require them
    # For example: libyajl-dev for json-related plugins, zlib1g-dev, etc.
    # Check Volatility3 documentation for specific system requirements if you encounter errors.
    && rm -rf /var/lib/apt/lists/*

# Clone Volatility3 repository (adjust this if you're installing via pip or have a different setup)
# This assumes Volatility3 is not installed via pip and runner.py expects 'vol' or 'volatility3' to be in PATH
RUN git clone https://github.com/volatilityfoundation/volatility3.git /opt/volatility3 \
    && cd /opt/volatility3 && pip install .

# Add Volatility3 to the PATH
ENV PATH="/opt/volatility3:$PATH"

# Copy the requirements file and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your application files into the container
COPY . .

# Create directories for memory dumps and output results
# These will be empty initially but allow Streamlit to create subdirectories.
RUN mkdir -p memory out

# Expose the port Streamlit runs on (default is 8501)
EXPOSE 8501

# Command to run the Streamlit application
# We use 'sh -c' to ensure that environment variables for Volatility3 are picked up
# Removing --server.address 127.0.0.1 to allow Streamlit to bind to 0.0.0.0 internally,
# and securing access via the docker run command.
CMD ["sh", "-c", "streamlit run app.py --server.port 8501 --server.enableCORS false --server.enableXsrfProtection false"]

