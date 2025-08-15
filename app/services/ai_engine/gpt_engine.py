import os
import openai

def _get_openai_client():
    """Get OpenAI client with API key."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable is not set")
    openai.api_key = api_key
    return openai

def gpt_generate_config(user_input: str) -> str:
    try:
        openai_client = _get_openai_client()
        response = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a Cisco network automation assistant. "
                        "The user will ask for network changes in natural language. "
                        "Respond ONLY with the correct Cisco CLI configuration. "
                        "DO NOT explain anything. DO NOT include comments. DO NOT greet or thank the user. "
                        "when the user ask to remove all the default routes,ONLY show 'no ip route 0.0.0.0 0.0.0.0'"
                        
                    )
                },
                {"role": "user", "content": user_input}
            ],
            temperature=0.2,
            max_tokens=150
        )

        result = response.choices[0].message.content.strip()

        if result.startswith("```"):
            result = result.strip("`")
            if "\n" in result:
                result = result.split("\n", 1)[1]

        return result.strip()

    except Exception as e:
        return f"Error: {str(e)}"

def gpt_conversational_with_config(user_input: str) -> dict:
    try:
        config_response = gpt_generate_config(user_input)

        return {
            "voice_reply": config_response,
            "cli_config": config_response
        }

    except Exception as e:
        return { "error": str(e) }

def gpt_generate_show_command(question: str) -> str:
    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a Cisco expert. Convert user questions into a single valid Cisco IOS show command. "
                        "Reply only with the command. Do not explain anything."
                        "When the user ask 'show me the ospf, eigrp, rip, bgp configs'. Respond with show running-config | section ospf output unless, the user ask for something specific."
                        "When the user say 'pink, think' that mean 'ping' like 'ping 192.168.56.10' "
                        "If the user asks for 'domain name' like  'what the domain name is', please show the users ' sho run | section ip domain'"
                        " when the user ask to find default routes or say default routes, show 'show run | section ip route'"
                    )
                },
                {"role": "user", "content": question}
            ],
            temperature=0.2,
            max_tokens=100
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"Error: {str(e)}"
