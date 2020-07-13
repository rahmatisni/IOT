import pandas
import json
import sqlalchemy
from flask import jsonify

from flask import Flask

app = Flask(__name__)


# endpoint to create new user
@app.route("/asd", methods=["POST"])
def add_lokasi():
    aku = request.body['aku']
    kamu = request.body['kamu']
    hasil = aku + kamu
    
    return hasil
if __name__ == '__main__':
    app.run(debug=True)