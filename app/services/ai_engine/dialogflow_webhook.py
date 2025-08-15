from fastapi import Request
from fastapi.responses import JSONResponse
from app.services.ai_engine.gpt_engine import gpt_generate_config
async def dialogflow_webhook(request: Request):
   try:
       request_json = await request.json()
       # Get text input from Dialogflow
       text = (
           request_json.get("text") or
           request_json.get("fulfillmentInfo", {}).get("tag") or
           request_json.get("sessionInfo", {}).get("parameters", {}).get("query")
       )
       if not text:
           text = "create vlan 100"  # fallback default
       config = gpt_generate_config(text)
       return JSONResponse({
           "fulfillment_response": {
               "messages": [{
                   "text": {
                       "text": [f"Here is the config: ```{config}```"]
                   }
               }]
           }
       })
   except Exception as e:
       return JSONResponse({
           "fulfillment_response": {
               "messages": [{
                   "text": {
                       "text": [f"❌ Error: {str(e)}"]
                   }
               }]
           }
       })