import requests
class virustotal:


    def ipcheck(self):
        url = 'https://www.virustotal.com/api/v3/ip_addresses/152.67.1.30'
        params = {'x-apikey': '048a7733c2da19bff202268d9c1c652834f448354e2c456b16ae768932136b06'}
        response = requests.get(url, headers=params)
        if response.status_code == 200:
            output = response.json()
            if output !=0:
                print(f'regional_internet_registry={output["data"]["attributes"]["regional_internet_registry"]}')
                print(f'jarm={output["data"]["attributes"]["jarm"]}')
                print(f'network={output["data"]["attributes"]["network"]}')
                print(f'country={output["data"]["attributes"]["country"]}')
                print(f'last_analysis_stats={output["data"]["attributes"]["last_analysis_stats"]}')

            else:
                print('nothing to display')
        else:
            print(f'error status code={response.status_code} | reason={response.reason}')


    def domaincheck(self):
        url = 'https://www.virustotal.com/api/v3/domains/www.google.com'
        params = {'x-apikey':'048a7733c2da19bff202268d9c1c652834f448354e2c456b16ae768932136b06'}
        response = requests.get(url, headers=params)
        if response.status_code == 200:
            output = response.json()
            print(output)
        else:
            print(f'error status code={response.status_code} | reason={response.reason}')

# obj1 = virustotal()
#
# obj1.ipcheck()

obj2 = virustotal()
obj2.domaincheck()
