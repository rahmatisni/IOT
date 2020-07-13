import time
import pandas as pd

def executeSomething():
    #code here
    data = pd.read_csv (r'/home/rahmat/server1-01.csv')   #read the csv file (put 'r' before the path string to address any special characters in the path, such as '\'). Don't forget to put the file name at the end of the path + ".csv"

    df = pd.DataFrame(data)
    print(df)
    df.to_json (r'/home/rahmat/hasil.json')
    time.sleep(4)

while True:
    executeSomething()



