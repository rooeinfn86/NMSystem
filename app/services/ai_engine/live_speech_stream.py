import os
import queue
import sounddevice as sd
import numpy as np
from google.cloud import speech
from google.oauth2 import service_account

# Set your Google Cloud credentials path
os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "cisco-ai-voice-673380c854bd.json"

# Audio settings
RATE = 16000
CHUNK = int(RATE / 10)  # 100ms
DEVICE_INDEX = 8  # Replace with your working mic index from device list

# Initialize the queue for audio data
q = queue.Queue()

# Google Cloud Speech client
credentials = service_account.Credentials.from_service_account_file(
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
)
client = speech.SpeechClient(credentials=credentials)

# Configure audio input
config = speech.RecognitionConfig(
    encoding=speech.RecognitionConfig.AudioEncoding.LINEAR16,
    sample_rate_hertz=RATE,
    language_code="en-US"
)

streaming_config = speech.StreamingRecognitionConfig(
    config=config,
    interim_results=True
)

def callback(indata, frames, time, status):
    volume = np.linalg.norm(indata) * 10
    print(f"\U0001F4E3 Mic volume: {volume:.6f}")
    try:
        q.put(indata.copy())
    except Exception as e:
        print(f"Callback error: {e}")

def audio_generator():
    try:
        while True:
            chunk = q.get()
            if chunk is None:
                break
            yield speech.StreamingRecognizeRequest(audio_content=chunk.tobytes())
    except Exception as e:
        print(f"\u274C Error generating audio: {e}")

def listen_print_loop(responses):
    for response in responses:
        if not response.results:
            continue
        result = response.results[0]
        if not result.alternatives:
            continue
        transcript = result.alternatives[0].transcript
        print(f"\U0001F5E3️ You said: {transcript}")

def recognize_stream():
    try:
        print("\U0001F3A4 Warming up the microphone...")
        with sd.InputStream(samplerate=RATE, blocksize=CHUNK, dtype='int16',
                            channels=1, callback=callback, device=DEVICE_INDEX):
            print("\U0001F3A4 Say something (Ctrl+C to stop)...")
            requests = audio_generator()
            responses = client.streaming_recognize(streaming_config, requests)
            listen_print_loop(responses)
    except Exception as e:
        print(f"\u274C Error: {e}")

if __name__ == "__main__":
    recognize_stream()
