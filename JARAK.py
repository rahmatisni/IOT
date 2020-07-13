import json

with open('hasil.json') as f:
  data = json.load(f)


json_string = json.dumps(data)
print(json_string)