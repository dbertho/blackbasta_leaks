import argparse
import json
import os
from deep_translator import GoogleTranslator
from time import sleep

def translate(text):
    translation = GoogleTranslator(source='auto', target='en').translate(text)
    print(translation)
    return translation

def process_json_file(input_path):
    base_filename = os.path.splitext(os.path.basename(input_path))[0]
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        print(len(data))
    
    with open('translated_log.json', 'a+', encoding="utf8") as outfile:
        outfile.write("\n") 
        for item in data:
            print(item)
            if 'message' in item:
                original_message = item['message']
                if original_message != '':
                    try:
                        # Google translate API cannot process more than 5000 characters. For the sake of simplicity, I ignore everything after that limit
                        processed_message = translate(original_message[:4999])
                    except Exception as e:
                        print(f"Error: {e}")
                        # In rare instances, certain messages caused unexplained requests errors. These messages will not be translated.
                        processed_message = original_message
                else:
                    processed_message = original_message
                item['message'] = processed_message
                item = dict(timestamp=item["timestamp"],chat_id=item["chat_id"],sender_alias=item["sender_alias"],message=item["message"])
                outfile.write(json.dumps(item, ensure_ascii = False).encode('utf8').decode())
                outfile.write(",\n")
                # Timer added to avoid hitting API quota
                sleep(0.1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Translating a JSON transcript')
    parser.add_argument('file', help='The file to translate.')
    args = parser.parse_args()
    process_json_file(args.file)
