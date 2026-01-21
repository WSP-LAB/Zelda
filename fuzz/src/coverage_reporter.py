import os 
import platform
import csv 
from bs4 import BeautifulSoup
import requests

class CoverageReporter():
    def __init__(self, url, mode, root_url, session):
        self.root_url = root_url
        self.session = session
        #self.session.get(self.root_url + "save-coverage-lines.php?flag=stop")
        self.session.get(self.root_url + "save-coverage-lines.php?flag=start&folder=" + url.replace(":","").split("/")[1])
        if platform.system() == "Windows":
            print("windows")
            file_name_vul = "logs\'" + url.replace("http://","").split("/")[1] + "-cov-" + mode 
        else:
            file_name_vul = "logs/" + url.replace("http://","").split("/")[1]+ "-cov-" + mode 
        file_ext = ".csv"

        uniq = 1
        output_path = file_name_vul + "-1" + file_ext

        while os.path.exists(output_path):
            uniq += 1 
            output_path = "%s-%d%s" % (file_name_vul, uniq, file_ext)
    
        file_name_vul = "%s-%d%s" % (file_name_vul, uniq, file_ext)

        self.log_cov = open(file_name_vul, "w")
        
        self.wr = csv.writer(self.log_cov)

    def log_coverage(self, time): 
        coverage = self.parse_coverage_report_html() 
        self.wr.writerow([time, coverage]) 
        self.log_cov.flush()

    def parse_coverage_report_html(self):
        import requests
        response = requests.get(self.root_url + "report")
     
        soup = BeautifulSoup(response.text, "html.parser")
        try:
            tbody = soup.find("tbody")
            first_tr = tbody.find("tr")
            first_span = str(first_tr.find("span"))
            coverage = float(first_span.split(">")[1].split("%")[0])
        except:
            coverage = 0
        return coverage

    def parse_coverage_report_txt(self):
        import requests
        response = requests.get(self.root_url + "report.txt")
        cover_repo = response.text
        covered_lines = float(cover_repo.split("Lines:")[1].split("%")[0].replace(" ",""))
        """
        try:
            response = self.session.get(self.root_url + "save-coverage-lines.php?flag=coverage")
            covered_lines = int(response.text)
            
        except:
            covered_lines = 0
        """

        #print(int(cover_repo.split("Lines:")[1].replace(" ","").split("(")[1].split("/")[0]))
        return covered_lines

if __name__ == '__main__':
    cr = CoverageReporter("", "black","", requests.Session())
    cr.parse_coverage_report_txt()