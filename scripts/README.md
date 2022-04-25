Here are various scripts used for training decision tree and random forests.

- ML.ipynb is jupyter notebook file used to train randomforests.

It will also write the decision trees in .dot files

-  rftop4_v2.py is a python file. It will read the randomforest file saved using pickle tool (see at the end of the notebook) and convert it into P4 rules.  The code may need to be adapted to different number of trees in the trained random forest.


# How do we convert a decision tree to P4 rules?

Please check the paper: https://hal.archives-ouvertes.fr/hal-02968593/document.
For example section 4.1 describes node id, previous feature id etc.

Let us consider an example decision tree found in ML.ipynb:
TREE 0
|--- feature_9 <= 0.02
| |--- feature_4 <= 0.50
| | |--- feature_1 <= 1.00
...
...
|--- feature_9 > 0.02
| |--- feature_2 <= 156.00


Corresponding P4 rules look like the following.
table_add MyIngress.level1 MyIngress.CheckFeature 0 0 1 => 1 9 20000
table_add MyIngress.level2 MyIngress.CheckFeature 1 9 1 => 2 4 0
table_add MyIngress.level3 MyIngress.CheckFeature 2 4 1 => 3 1 1

It corresponds to one branch of the following tree. It is saying on node 1 if feature 9 was less than equal to 20000 (0.02 in the tree) then result = 1 (in P4 program meta.isTrue = 1)

Next time in rule it will match the key 1 9 1 (node id , feature id, isTrue)
Thus, it will match and will go to node 2 and check for feature 4 with 0 as threshold (it is binary so <= 0 is equivalent to <=0.50)

In case it was more than 20000 then it will match another rule and will check feature 2:
table_add MyIngress.level2 MyIngress.CheckFeature 1 9 0 => 99 2 156

If you want to add your own new feature then you may just create a new feature id for your features. 
Think of adding rules for them and then add the check in the end of the checkfeature function.
