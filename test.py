from sklearn.ensemble import RandomForestClassifier

import numpy as np



domainlist = []

class Domain:

	def __init__(self,_length,_num, _label):

		self.domainName_length = _length

		self.num_of_domainName = _num

		self.label = _label



	def returnData(self):

		return [self.domainName_length, self.num_of_domainName]

        

	def returnLabel(self):

		if self.label == "notdga":

			return "notdga"

		else:

			return "dga"



		

def initData(filename):

	with open(filename) as f:

		for line in f:

			num_of_domainName = 0;

			line = line.strip()

			if line.startswith("#") or line =="":

				continue

			tokens = line.split(",")

			domainName_length = len(tokens[0])

			for i in tokens[0]:

                        	if i.isdigit():

                                	num_of_domainName += 1

			label = tokens[1]

			domainlist.append(Domain(domainName_length,num_of_domainName,label))



#def runData(filename1,filename2,c):

		

def main():

	initData("train.txt")

	featureMatrix = []

	labelList = []

	for item in domainlist:

		featureMatrix.append(item.returnData())

		labelList.append(item.returnLabel())



	clf = RandomForestClassifier(random_state=0)

	clf.fit(featureMatrix,labelList)



	#runData("test.txt","result.txt",clf)

	with open("test.txt") as f1, open("result.txt", 'w') as f2:

		for line in f1:

			num = 0;

			if line.startswith("#") or line =="":

				continue

			length = len(line)

			for i in line:

				if i.isdigit():

					num += 1

			line = line.replace("\n","")

			line = line.replace("\r","")

			f = str(clf.predict([[length,num]]))

			f = f.replace("[","")

			f = f.replace("]","")

			f = f.replace("\'","")

			output = line + "," + f + "\n"

			f2.write(output)



if __name__ == '__main__':

	main()

	
