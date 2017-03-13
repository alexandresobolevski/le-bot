# Copy and rename as credentials.sh
# Set your DNS_DOMAIN and ZONE_NAME
# Run `source credentials.sh && python le_server.py`

# These are always required to run the bot.
export DNS_DOMAIN="your-domain.com"
export ZONE_NAME="zone-name"

# These are required to run tests locally.
export PLOTLY_API_DOMAIN="https://api.plot.ly"
export PLOTLY_API_KEY="longSTRING123"
export PLOTLY_ACCESS_TOKEN="veryLONGstring123456"
export PLOTLY_USERNAME="johndoe"
