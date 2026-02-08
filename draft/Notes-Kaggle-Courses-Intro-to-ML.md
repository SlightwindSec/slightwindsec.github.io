---
title: "Notes: Kaggle Courses - Intro to ML & Intermediate ML"
date: 2022-03-10 16:23:00
category: "Notes"
math: true
tags: ["Notes", "Kaggle", "MachineLearning"]
banner_img: https://p2.qhimg.com/bdm/1600_900_85/t016c5b68d9192978db.jpg
---

# Intro to Machine Learning L

## How Models Work

介绍了当前这篇教程的内容和受众，然后举例说明ml可以做什么，可以使用模型，来代替人对各种类型的房屋价值进行估计。然后用简单的决策树对房屋分类，预测不同房屋的价值。

从数据中提取模式的过程这一步骤称为**拟合**(fitting)或**训练**(training)模型，用于拟合模型的数据称为训练数据(training data)。

## Basic Data Exploration

### Using Pandas to Get Familiar With Your Data

这里开始讲pandas，一般会把它缩写为`pd`，可以使用pandas来帮助我们熟悉数据。pandas中有一个重要的概念“DataFrame”，可以把它类比成Excel中的工作表，或者SQL数据库中的table，pandas的功能很强大。

给了一个简单使用pandas的例子：
```python
# save filepath to variable for easier access
melbourne_file_path = '../input/melbourne-housing-snapshot/melb_data.csv'
# read the data and store data in DataFrame titled melbourne_data
melbourne_data = pd.read_csv(melbourne_file_path) 
# print a summary of the data in Melbourne data
melbourne_data.describe()
```

### Interpreting Data Description

这里就是解释了一下上面这个例子中，各个列的含义，然后提到了缺失值。

有些位置可能会出现一些缺失值，这确实是符合现实情况的，比如泰坦尼克号的数据中，有些人的数据收集不全了，这种时候可以通过一些方法把它填上。然后看到有篇文章讲到缺失值可以通过其他的比较全的数据作为X，缺失值对应的特征作为y，来简单构建一个模型预测一下，从而达到通过其他信息补上可能性比较大的值的操作。

## Your First Machine Learning Model

### Selecting Data for Modeling

有些时候数据中会有太多的变量，这些变量不一定是我们的模型所需要的，应该通过一些方法来选择对我们训练模型有价值的变量。

```python
import pandas as pd

melbourne_file_path = '../input/melbourne-housing-snapshot/melb_data.csv'
melbourne_data = pd.read_csv(melbourne_file_path) 
melbourne_data.columns
'''
Index(['Suburb', 'Address', 'Rooms', 'Type', 'Price', 'Method', 'SellerG',
       'Date', 'Distance', 'Postcode', 'Bedroom2', 'Bathroom', 'Car',
       'Landsize', 'BuildingArea', 'YearBuilt', 'CouncilArea', 'Lattitude',
       'Longtitude', 'Regionname', 'Propertycount'],
      dtype='object')
'''
```

关于axis参数，推荐阅读 https://railsware.com/blog/python-for-machine-learning-pandas-axis-explained/ 来详细了解，简单来说，axis是用来选择**行/列**的。

可以使用`dropna()`把包含缺失值的**行/列**直接删除，首先创建一个在`3`行`b`列出现了缺失值的DataFrame，可以通过改变axis的值，选择删除`3`行，或者删除整个`b`列。

```python
>>> import pandas as pd
>>> import numpy as np
>>> srs_a = pd.Series([10,30,60,80,90])
>>> srs_b = pd.Series([22, 44, 55, np.nan, 101])
>>> df = pd.DataFrame({'a': srs_a, 'b': srs_b})
>>> df
    a      b
0  10   22.0
1  30   44.0
2  60   55.0
3  80    NaN
4  90  101.0
>>> df.dropna(axis=0) # 删除`3`行
    a      b
0  10   22.0
1  30   44.0
2  60   55.0
4  90  101.0
>>> df.dropna(axis=1) # 删除`b`列
    a
0  10
1  30
2  60
3  80
4  90
```

> 其实也可以使用 `pd.np` 来访问到numpy，但是会提示将来的版本会不再支持这样导入，所以为了代码在将来的版本可以运行，更推荐单独导入numpy

### Selecting The Prediction Target


我们将使用点符号来选择我们想要预测的列，这称为**预测目标**。按照惯例，预测目标称为 **y**。所以我们需要保存墨尔本数据中房价的代码是

```python
y = melbourne_data.Price 
```

### Choosing "Features"

输入到我们模型中的列称为“特征”，在我们的例子中，这些将是用于确定房价的列。有些时候会使用除目标之外的所有列作为特征。也有些时候使用更少的特征训练效果会更好。

按照惯例，训练数据称为 **X**。

```python
melbourne_features = ['Rooms', 'Bathroom', 'Landsize', 'Lattitude', 'Longtitude']
X = melbourne_data[melbourne_features]
```
可以再使用 `X.describe()` 来大概看一下数据的数量、平均值等信息，以及使用`X.head()`来查看表的最前面几行。


### Building Your Model

下面使用scikit-learn来创建和训练模型，在代码中使用它的简称`sklearn`，sklearn可以直接处理存储在DataFrame中的数据。

构建和使用模型的步骤是：
* **Define**：它将是什么类型的模型？以及指定模型类型的一些参数。
* **Fit**：从提供的数据中获取模式。这是建模的核心部分。
* **Predict**：通过未知的X预测出对应的y
* **Evaluate**：确定模型的预测有多准确。

这是一个使用 scikit-learn 定义决策树模型并将其与特征和目标变量拟合的示例。

```python
from sklearn.tree import DecisionTreeRegressor

# Define model. Specify a number for random_state to ensure same results each run
melbourne_model = DecisionTreeRegressor(random_state=1)
melbourne_model.fit(X, y) # Fit model
print("Making predictions for the following 5 houses:")
print(X.head())
print("The predictions are")
print(melbourne_model.predict(X.head()))
```

> Many machine learning models allow some randomness in model training. Specifying a number for random_state ensures you get the same results in each run. This is considered a good practice. You use any number, and model quality won't depend meaningfully on exactly what value you choose.

## Model Validation

### What is Model Validation

常常需要评估自己构建的模型，来验证自己的模型在预测时的准确性，不应该使用训练数据进行预测，这样会得到较准确的预测结果，但是很可能在预测新数据的时候有很大的偏离，一般来说常用的方法是按照一定比例分离自己拥有的数据，一部分用于训练，一部分用来验证，训练过程不应该让模型接触到验证数据。

总结模型质量的指标有很多，但我们从一个称为**平均绝对误差**（也称为 **MAE**）的指标开始。让我们从最后一个词 error 开始分解这个指标。每栋房屋的预测误差为： error=actual−predicted

使用 MAE 度量，取每个error的绝对值，然后我们计算这些绝对误差的平均值。

```python
from sklearn.metrics import mean_absolute_error

predicted_home_prices = melbourne_model.predict(X)
mean_absolute_error(y, predicted_home_prices)
```

> 这里有个 The Problem with "In-Sample" Scores，也是在说明不应该使用训练数据去验证模型的效果


### Coding It

scikit-learn 库有一个函数 `train_test_split` 将数据分成两部分。 我们将使用其中一些数据作为训练数据来拟合模型，使用其他数据作为验证数据来计算 `mean_absolute_error`。

```python
from sklearn.model_selection import train_test_split

train_X, val_X, train_y, val_y = train_test_split(X, y, random_state = 0)
# Define model
melbourne_model = DecisionTreeRegressor()
# Fit model
melbourne_model.fit(train_X, train_y)

# get predicted prices on validation data
val_predictions = melbourne_model.predict(val_X)
print(mean_absolute_error(val_y, val_predictions)) # 258930.03550677857
```

## Underfitting and Overfitting

这一部分讲模型的欠拟合和过拟合，尽量避免这两种情况可以优化模型的性能。

### Experimenting With Different Models

有了前面衡量模型准确性的指标（MAE），就可以通过选择不同的模型，或者使用不同的参数，来训练出更好的模型。

比如scikit-learn的决策树模型，我们可以更改树的深度，树的深度是衡量它在进行预测之前进行了多少次分割的量度。比如分割1次，就是分割成了2种情况，分割2次就是4种情况，10次即1024种。。。也就是一棵二叉树叶子节点的数量。比如通过房屋的各种特征来分割，分的种类越多，平均下来每个种类的房屋的数量就越少，如果本就不多的训练数据被分成了1024类，**模型几乎完美地匹配训练数据**，对于新数据很可能做出不准确的预测，这就是**过度拟合**（Overfitting）的现象，

如果一棵决策树只将房屋分成2种或4种情况，每组中会有各种各样的房屋，模型不能详细的体现数据中的重要区别和模式，在用验证数据或训练数据评估时都会发现效果不佳，这称为**欠拟合**（Underfitting）。

由于我们希望可以准确地预测新数据，我们希望找到欠拟合和过拟合之间的最佳点，也就是下图中（红色）验证曲线的低点。

![](https://s1.ax1x.com/2022/03/26/qUYgW6.png)

### Example

也有方法可以让树的某些路径的深度大于另一些路径的深度，`max_leaf_nodes`提供了一种非常明智的方法来控制欠拟合和过拟合，我们允许模型生长出的叶子数量越多，从上图中的**欠拟合区域**移动到**过拟合区域**的距离就越多。这样就可以通过调节`max_leaf_nodes`，来获取最佳MAE分数。

```python
from sklearn.metrics import mean_absolute_error
from sklearn.tree import DecisionTreeRegressor

def get_mae(max_leaf_nodes, train_X, val_X, train_y, val_y):
    model = DecisionTreeRegressor(max_leaf_nodes=max_leaf_nodes, random_state=0)
    model.fit(train_X, train_y)
    preds_val = model.predict(val_X)
    mae = mean_absolute_error(val_y, preds_val)
    return(mae)
for max_leaf_nodes in [5, 50, 500, 5000]:
    my_mae = get_mae(max_leaf_nodes, train_X, val_X, train_y, val_y)
    print("Max leaf nodes: %d  \t\t Mean Absolute Error:  %d" %(max_leaf_nodes, my_mae))
```
从下面的输出结果可以看出，在这些选择中，500是最好的选择。
```
Max leaf nodes: 5  		 Mean Absolute Error:  347380
Max leaf nodes: 50  		 Mean Absolute Error:  258171
Max leaf nodes: 500  		 Mean Absolute Error:  243495
Max leaf nodes: 5000  		 Mean Absolute Error:  254983
```

### Conclusion

* **Overfitting**: capturing spurious patterns that won't recur in the future, leading to less accurate predictions, or
* **Underfitting**: failing to capture relevant patterns, again leading to less accurate predictions.

可以用验证数据，去评估模型的性能，为模型选择尽可能适合的参数。

## Random Forests

### Introduction

随机森林使用多个树，它通过平均每个树的预测来进行预测。 通常比单个决策树具有更好的预测精度，并且可以很好地使用默认参数。

```python
from sklearn.ensemble import RandomForestRegressor
from sklearn.metrics import mean_absolute_error

forest_model = RandomForestRegressor(random_state=1)
forest_model.fit(train_X, train_y)
melb_preds = forest_model.predict(val_X)
print(mean_absolute_error(val_y, melb_preds))

# 191669.7536453626
```
把之前的决策树类`DecisionTreeRegressor`替换成随机森林类`RandomForestRegressor`，可以发现即使是直接使用默认参数，也可以得到优于之前（MAE=258930.03550677857）的结果（MAE=191669.7536453626）。

## Machine Learning Competitions

这里就是一个讲在kaggle上如何参加比赛的教程，跟着做一遍就会在kaggle的服务器上训练模型并得到最后的结果，然后可以提交结果看到排名。


# Intermediate Machine Learning

## Introduction

* 解决现实世界数据集中经常出现的数据类型（缺失值、分类变量），
* 设计**pipelines**以提高机器学习代码的质量，
* 使用先进的模型验证技术（cross-validation，交叉验证），
* 构建广泛用于赢得Kaggle竞赛的最先进模型（XGBoost），
* 避免常见和重要的数据科学错误（leakage）。

## Missing Values

这节教程会介绍3种处理缺失值的方法，在现实世界的数据中，很多情况会存在缺失值：

* 一套两卧室的房子，不会包含第三个卧室的大小数据
* 调查对象可以选择不提供自己的收入

### Three Approaches

#### 1) A Simple Option: Drop Columns with Missing Values

直接把含有缺失值的列（特征）删除，这个方法很简单，但是可能会直接导致重要的特征丢失。

#### 2) A Better Option: Imputation

Imputation指用一些数字填充缺失的值。例如，我们可以在NaN处填写每列的平均值。

#### 3) An Extension To Imputation

在方法2的基础上，再插入一列，用True/False来表示存在缺失值这一列对应的数据是否缺失，这个方法有时候表现良好，也有时候不好。

我在其他地方还看到一种方法感觉比较好，可以称为方法4，把存在缺失值的这一列，作为target，其他不存在缺失值的列，作为特征，以存在缺失值这一列的其他不缺失的数据作为训练集和验证集，把缺失的行作为test集来为其预测并填充，这样可以得到尽可能准确的填充。

当然最好是具体问题具体分析，比如某个存在缺失值的数据与预测目标相关性不大，或者缺失值太多，并且类型不方便预测，比如是姓名，就可以直接将这一列删除。如果是第3个卧室的问题（房型只有两个卧室），可以把它的面积置为0，来表示它不存在，如果把它设置为第3个卧室的平均大小，对其他房间小的数据来说太不公平。。。如果某列特征方差比较小，也可以直接取平均值填充来使模型正常运行。

测试了3种填充方法，在同一模型下预测的结果，可以看出来方法3比方法2稍差，但是差距并不大。
```
MAE from Approach 1 (Drop columns with missing values):
183550.22137772635

MAE from Approach 2 (Imputation):
178166.46269899711

MAE from Approach 3 (An Extension to Imputation):
178927.503183954
```
## Categorical Variables

我们会遇到很多非数值型数据，这些数据我们也可以将它们应用到机器学习中，在这节教程里会介绍处理分类变量的三种方法。

分类变量只接受有限数量的值，比如询问早餐的频率“从不”、“很少”、“大多数”或“每天”，或者对车的品牌进行调查，得到的回答是各个品牌。

### Three Approaches

#### 1) Drop Categorical Variables

删掉分类变量。。。。

#### 2) Ordinal Encoding

顺序编码将每个唯一值分配给不同的整数。

<img src="https://s1.ax1x.com/2022/03/26/qUYjOg.png">

这种方法假定类别的排序：“从不”（0）<“很少”（1）<“大多数天”（2）<“每天”（3）。对这样的分类进行排名是没有争议的，我们可以把描述频率的词汇对应到数值上，模型也将会很好的处理这些数据。

#### 3) One-Hot Encoding

One-Hot编码的方法是创建一些新的列来代替原来的列，这些新的列名为具体的分类，值为存在/不存在，比如下面这个图示：

<img src="https://s1.ax1x.com/2022/03/26/qUYzwj.png">

所以对于没有顺序的分类，可以使用One-Hot编码这种方式来对分类进行数值化。但是它的缺点也很明显，如果分类很多，那么进行One-Hot编码后会出现很多新的列，这些列组成的矩阵将是个很稀疏的矩阵，这个时候可能模型会表现的不好。
```
MAE from Approach 1 (Drop categorical variables):
175703.48185157913

MAE from Approach 2 (Ordinal Encoding):
165936.40548390493

MAE from Approach 3 (One-Hot Encoding):
166089.4893009678
```
方法2和方法3在这里的数据中并没有出现明显的差距，但是很明显都优于直接删除。

## Pipelines

Pipelines是一个可以把数据预处理和创建模型组装到一起的工具，可以：使代码更整洁，更少的bug，更容易部署，更多验证模型的选择。

第一步，定义数据预处理的过程

```python
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OneHotEncoder

# Preprocessing for numerical data
numerical_transformer = SimpleImputer(strategy='constant')

# Preprocessing for categorical data
categorical_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='most_frequent')),
    ('onehot', OneHotEncoder(handle_unknown='ignore'))
])

# Bundle preprocessing for numerical and categorical data
preprocessor = ColumnTransformer(
    transformers=[
        ('num', numerical_transformer, numerical_cols),
        ('cat', categorical_transformer, categorical_cols)
    ])
```

第二步，定义模型

```python
from sklearn.ensemble import RandomForestRegressor

model = RandomForestRegressor(n_estimators=100, random_state=0)
```

第三步，创建并评估Pipeline

```python
from sklearn.metrics import mean_absolute_error

# Bundle preprocessing and modeling code in a pipeline
my_pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                              ('model', model)
                             ])

# Preprocessing of training data, fit model 
my_pipeline.fit(X_train, y_train)

# Preprocessing of validation data, get predictions
preds = my_pipeline.predict(X_valid)

# Evaluate the model
score = mean_absolute_error(y_valid, preds)
print('MAE:', score)
```

## Cross-Validation

如果碰巧抽出的部分验证集数据有些特殊，而我们对于模型和参数的选择是基于验证集的，可能会干扰我们的决策。

### What is cross-validation?

在交叉验证中，我们在不同的数据子集上运行建模过程，以获得模型质量的多个度量。例如，我们可以首先将数据分成5个部分，每个部分占整个数据集的20%。在这种情况下，我们说我们已经将数据分成5个“折叠”。

<img src="https://s1.ax1x.com/2022/03/26/qUYrw9.png">

1. 在`Experiment 1`中，我们用`1st fold`，作为验证集，其他80%作为训练集对模型进行训练，并用验证集评估。
2. 在`Experiment 2`中，我们用`2nd fold`，作为验证集，其他80%作为训练集对模型进行训练，并用验证集评估。
3. 重复这个过程，就可以得到不同的5个验证集上的结果，用这个结果来评估当前的模型（参数）会更加合理。

### When should you use cross-validation?

- 对于比较小的数据集，折叠多次 也就是训练多次不会对计算造成太大负担，可以使用交叉验证。
- 对于比较大的数据集，多次折叠会导致耗费大量的时间，并且既然数据集很大，分割出来的这部分验证集应该会具有不错的随机性，所以只用验证一次即可。

使用Pipelines可以很方便的进行交叉验证，不使用Pipelines的交叉验证代码会比较复杂。

```python
from sklearn.ensemble import RandomForestRegressor
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

my_pipeline = Pipeline(steps=[('preprocessor', SimpleImputer()),
                              ('model', RandomForestRegressor(n_estimators=50,
                                                              random_state=0))
                             ])
```

我们使用sklearn中的cross_val_score()函数获得交叉验证分数，使用cv参数设置折叠的数量。

```python
from sklearn.model_selection import cross_val_score

# Multiply by -1 since sklearn calculates *negative* MAE
scores = -1 * cross_val_score(my_pipeline, X, y,
                              cv=5,
                              scoring='neg_mean_absolute_error')

print("MAE scores:\n", scores)
```

```
MAE scores:
 [301628.7893587  303164.4782723  287298.331666   236061.84754543
 260383.45111427]
```

`scoring`参数可以选择评估的标准，参考[sklearn的文档](http://scikit-learn.org/stable/modules/model_evaluation.html)可以了解支持的其他选择。这里我们指定的是**negative mean absolute error (MAE)**。

> sklearn 约定评估分数的时候，数值越大越好，MAE属于是越小越好的标准，所以sklearn选择只提供`negative MAE`，来保持自己的约定，我们在使用的时候，取 neg_mean_absolute_error 然后乘 -1 即可。

通常需要单一指标来评估模型，所以可以取它们的平均值：

```python
print("Average MAE score (across experiments):")
print(scores.mean())
```

## XGBoost

我们之前在很多练习中应用了随机森林模型，这种方法被称为“集成方法”（**ensemble method**），根据定义，集成方法集成了多个模型的预测。随机森林就是集成了多个决策树的预测，接下来，将学习另一种称为梯度增强（**gradient boosting**）的集成方法。

### Gradient Boosting

梯度增强是一种通过循环将模型迭代地添加到集合中的方法。

它会被初始化为只有一个模型的集合，它的预测十分不准确，但是后续对这个集合的添加会解决这个问题。

接下来开始循环：
- 首先，我们用集合内的每个模型为数据集生成预测，并把这些预测相加。这些预测用于计算损失函数（例如，均方误差）。
- 然后，我们使用损失函数来拟合一个新模型，并把该模型添加到集合中。具体来说，我们确定模型参数并将新模型添加到集合中来减少损失。（注：“梯度增强”中的“梯度”指的是我们将使用损失函数的梯度下降来确定这个新模型中的参数。）
- 最后，我们将新模型添加到集合中...
- ...重复

<img src="https://s1.ax1x.com/2022/03/26/qUYLSf.png">

XGBoost 意为 extreme gradient boosting，它是gradient boosting的一种实现，具有一些专注于性能和速度的附加功能，sklearn有其他版本的gradient boosting，但XGBoost有一些技术优势。

### Example

```python
from xgboost import XGBRegressor

my_model = XGBRegressor()
my_model.fit(X_train, y_train)
```

对模型进行预测和评估：

```python
from sklearn.metrics import mean_absolute_error

predictions = my_model.predict(X_valid)
print("Mean Absolute Error: " + str(mean_absolute_error(predictions, y_valid)))
```

```
Mean Absolute Error: 239435.01260125183
```

### Parameter Tuning

XGBoost有几个参数可以显著影响准确性和训练速度：

**n_estimators**
`n_estimators`指定了上述过程的周期数，同时它也是集合中模型的数量。
- 太低会导致欠拟合，对训练数据和测试数据的预测不准确。
- 太高会导致过拟合，对训练数据的预测很准确，但是对测试数据的预测比较差。
它的范围在100-1000，但是它的大小 很大程度上也取决于后面要讲的`learning_rate`参数。

```python
my_model = XGBRegressor(n_estimators=500) # 设置周期数为 500
my_model.fit(X_train, y_train)
```

**early_stopping_rounds**
`early_stopping_rounds`提供了自动找到理想的`n_estimators`的方法，当验证分数停止改善时，会提前停止迭代，所以我们可以设置一个比较大`n_estimators`，然后模型很可能会在这之前自动停止训练。由于训练过程具有一定的随机性，所以有时可能会某一轮没有提升，所以一般会设置`early_stopping_rounds=5`，即连续5轮验证分数都没有改善那么就停止训练。

在使用`early_stopping_rounds`的时候，要留出一部分数据来计算验证分数，这是由`eval_set`参数来完成的。

将上面提到的参数应用到模型中，来使模型提前停止：
```python
my_model = XGBRegressor(n_estimators=500)
my_model.fit(X_train, y_train, 
             early_stopping_rounds=5, 
             eval_set=[(X_valid, y_valid)],
             verbose=False)
```

**learning_rate**
我们可以将每个模型的预测乘以一个较小的数字（**learning rate**）然后再把它们相加。如果学习率比较小，会导致每个模型的预测对我们的帮助都比较小，所以我们应该在不会使它过拟合的前提下 设置尽可能高的学习率。

一般来说，较小的学习率和较大的模型集合将产生更精确的XGBoost模型，但这样会有较大的计算成本，更多的迭代，每次迭代耗费更长的时间，默认情况XGBoost会设置`learning_rate=0.1`。

```python
my_model = XGBRegressor(n_estimators=1000, learning_rate=0.05)
my_model.fit(X_train, y_train, 
             early_stopping_rounds=5, 
             eval_set=[(X_valid, y_valid)], 
             verbose=False)
```

**n_jobs**
在需要考虑运行时间的大型数据集上，可以将`n_jobs`设置为核心的数量，使用并行运算更快的构建模型。但是在较小的数据集上这样做不会有帮助。

```python
my_model = XGBRegressor(n_estimators=1000, learning_rate=0.05, n_jobs=4)
my_model.fit(X_train, y_train, 
             early_stopping_rounds=5, 
             eval_set=[(X_valid, y_valid)], 
             verbose=False)
```

## Data Leakage

这节教程会介绍数据泄露，以及如何防止数据泄露，如果不知道如何预防，那么数据泄露就会频繁出现，以微妙而危险的方式破坏模型。

当训练数据中包含有关target的信息时，会发生数据泄露，但当模型用于预测时，类似的数据将不可用。这将导致模型在训练集（甚至可能在验证集）上性能很高，但是在生产中性能较差。

泄漏主要有两种类型：**target leakage** 和 **train-test contamination**

### Target leakage

当训练的数据集中存在“在实际使用模型时不存在”的信息，并且这个信息对target有很强的相关性，这样会导致在训练集和测试集上效果都很好，但是在实际使用的时候，模型效果很差，比如下面这个例子：

假设要通过一些受访者的信息来判断他是否患有肺炎，下图是收集到的部分数据：

got_pneumonia | age | weight | male | took_antibiotic_medicine | ...
:--:  |:--:|:--: | :--:  | :--:  | :--:
False | 65 | 100 | False | False | ... 
False | 72 | 130 | True  | False | ... 
True  | 58 | 100 | False | True  | ...

其中`took_antibiotic_medicine`列和目标值`got_pneumonia`关系很强，因为如果得了肺炎那么他极大可能会吃药，训练过程就会根据吃药的行为判断他得了肺炎，这在实际应用模型时会发生判断不准确的现象，所以在使用数据训练模型的时候，要注意这些数据产生的时间需要是在“生产环境中使用模型进行预测的阶段”之前。

<img src="https://s1.ax1x.com/2022/03/26/qUtA6U.png">

### Train-Test Contamination

如果在数据预处理的时候，如果验证集也以某种方式参与了进来，比如在`train_test_split()`之前使用全部数据对空值插补，那么最后的模型很可能在训练集和验证集上表现良好，但在生产环境中表现较差。
