from io import StringIO
from numbers import Integral

import numpy as np
import pandas
import pickle 
import sklearn
from sklearn import tree 
from sklearn.tree import export_text

from sklearn.tree import _tree

from sklearn.tree import DecisionTreeClassifier

filename = 'final_rf_model.sav'
rf = pickle.load(open(filename, 'rb'))

i_tree = 0 

global_id = 0

def export_p4(decision_tree):
    tree_ = decision_tree.tree_
    class_names = decision_tree.classes_
    right_child_fmt = "{} {} <= {}\n"
    left_child_fmt = "{} {} >  {}\n"
    truncation_fmt = "{} {}\n"
    feature_names_ = ["{}".format(i) for i in tree_.feature]  
    export_text.report = ""
    max_depth=10
    spacing=3
    decimals=2
    show_weights=False

    if isinstance(decision_tree, DecisionTreeClassifier):
        value_fmt = "{}{} weights: {}\n"
        if not show_weights:
            value_fmt = "{}{}{}\n"
    else:
        value_fmt = "{}{} value: {}\n"

    def _add_leaf(value, class_name, indent, prevfeature, result, depth, previous_id):
        global global_id
        global i_tree 
        current_id = global_id

        val = ''
        is_classification = isinstance(decision_tree,
                                       DecisionTreeClassifier)
        if show_weights or not is_classification:
            val = ["{1:.{0}f}, ".format(decimals, v) for v in value]
            val = '['+''.join(val)[:-2]+']'
        if is_classification:
            val += ' class: ' + str(class_name)
        export_text.report += value_fmt.format(indent, '', val)
        print("table_add MyIngress.level_", i_tree,"_", depth, " ", "MyIngress.SetClass",i_tree," ", previous_id," ",prevfeature," ", result," ", "=>"," ", current_id, " ", int(float(class_name)), sep="")

    def print_tree_recurse(node, depth, prevfeature, result, previous_id):
        indent = ("|" + (" " * spacing)) * depth
        indent = indent[:-spacing] + "-" * spacing
        global global_id
        global i_tree 
        global_id = global_id + 1
        current_id = global_id

        value = None
        if tree_.n_outputs == 1:
            value = tree_.value[node][0]
        else:
            value = tree_.value[node].T[0]
        class_name = np.argmax(value)

        if (tree_.n_classes[0] != 1 and
                tree_.n_outputs == 1):
            class_name = class_names[class_name]

        if depth <= max_depth+1:
            info_fmt = ""
            info_fmt_left = info_fmt
            info_fmt_right = info_fmt

            if tree_.feature[node] != _tree.TREE_UNDEFINED:
                name = feature_names_[node]
                threshold = tree_.threshold[node]
                threshold = "{1:.{0}f}".format(decimals, threshold)
                export_text.report += right_child_fmt.format(indent,
                                                             name,
                                                             threshold)
                export_text.report += info_fmt_left
                if int(name) == 9 or int(name) == 11:
                   #print("**********", name, threshold, float(threshold), 1000000.0*float(threshold))
                   print("table_add MyIngress.level_", i_tree,"_", depth, " MyIngress.CheckFeature ", previous_id, " ", prevfeature, " ", result, " ", "=>", " ", current_id, " ", name," ", int(1000000.0*float(threshold)), sep='')

                else:
                   print("table_add MyIngress.level_", i_tree,"_", depth, " MyIngress.CheckFeature ", previous_id, " ", prevfeature, " ", result, " ", "=>", " ", current_id, " ", name," ", int(float(threshold)), sep='')

                print_tree_recurse(tree_.children_left[node], depth+1, name, 1, current_id)

                export_text.report += left_child_fmt.format(indent,
                                                            name,
                                                            threshold)
                export_text.report += info_fmt_right
           #     print("level", depth, "checkfeature", prevfeature, result, "=>", name, threshold)
 

                print_tree_recurse(tree_.children_right[node], depth+1, name, 0, current_id)
            else:  # leaf
                _add_leaf(value, class_name, indent, prevfeature, result, depth, previous_id)
        else:
            subtree_depth = _compute_depth(tree_, node)
            if subtree_depth == 1:
                _add_leaf(value, class_name, indent, prevfeature, result, depth, previous_id)
            else:
                trunc_report = 'truncated branch of depth %d' % subtree_depth
                export_text.report += truncation_fmt.format(indent,
                                                            trunc_report)

    print_tree_recurse(0, 1, 0, 1, global_id)


for tree_in_forest in rf.estimators_:
  #r = export_text(tree_in_forest)
  #print(r)
  global i_tree

  i_tree = i_tree + 1
  export_p4(tree_in_forest)
