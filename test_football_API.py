import json
import urllib3
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sb

http = urllib3.PoolManager()
def get_data(query, token):
    r = http.request('GET', 'api.football-data.org' + query, headers = { 'X-Auth-Token': token })
    return(json.loads(r.data))



competition = "PL"
#competition = "ELC"

token = 'a69bfd1640b141c2b5846be23e97a08b'
#season_filter = "?season=2020"
season_filter = "?season=2021"


teams = get_data(f"/v2/competitions/{competition}/teams{season_filter}", token)
matches = (get_data(f'/v2/competitions/{competition}/matches{season_filter}', token))
print(teams)
