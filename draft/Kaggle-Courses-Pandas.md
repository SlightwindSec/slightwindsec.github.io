---
title: "Notes: Kaggle Courses - Pandas"
date: 2022-03-09 16:23:00
category: "Notes"
math: true
tags: ["Notes", "Kaggle", "Pandas"]
---


# Pandas

## Creating, Reading and Writing

### Creating data

```python
import pandas as pd
```
[pandas](https://pandas.pydata.org/)是最受欢迎的python数据分析包。pandas中有两个核心对象**DataFrame**和**Series**。

**DataFrame**是一个表，由多个数组构成，这些数组常常作为表里面的列。使用`pd.DataFrame()`来实例化一个DataFrame对象，数据参数使用的是python中的`dict`，dict的key作为DataFrame的列名，dict的value是一个list，作为对应列的全部元素。

```python
>>> pd.DataFrame({'Yes': [50, 21], 'No': [131, 2]})
   Yes   No
0   50  131
1   21    2
>>> pd.DataFrame({'Bob': ['I liked it.', 'It was awful.'], 'Sue': ['Pretty good.', 'Bland.']})
             Bob           Sue
0    I liked it.  Pretty good.
1  It was awful.        Bland.
```
行的下标（通常称为索引(index)）默认和python的list一样，从0开始，也可以在构造时自定义
```python
>>> pd.DataFrame({'Bob': ['I liked it.', 'It was awful.'], 'Sue': ['Pretty good.', 'Bland.']}, 
                  index=['Product A', 'Product B'])
                     Bob           Sue
Product A    I liked it.  Pretty good.
Product B  It was awful.        Bland.
```

**Series**是一系列的数据，DataFrame是table，而Series是list，并且也可以设置index，但是没有列名，只可以设置一个name
```python
>>> pd.Series([1, 2, 3, 4, 5])
0    1
1    2
2    3
3    4
4    5
dtype: int64
>>> pd.Series([30, 35, 40], index=['2015 Sales', '2016 Sales', '2017 Sales'], name='Product A')
2015 Sales    30
2016 Sales    35
2017 Sales    40
Name: Product A, dtype: int64
```
可以将DataFrame视为粘在一起的Series。

### Reading data files

```python
wine_reviews = pd.read_csv("../input/wine-reviews/winemag-data-130k-v2.csv")
wine_reviews.shape # 输出行和列的数量

# (129971, 14)

wine_reviews.head() # 输出前几行的数据
```
`pd.read_csv()`的功能强大，可以指定30多个可选参数，比如可以设置csv文件的第0列作为索引：
```python
wine_reviews = pd.read_csv("../input/wine-reviews/winemag-data-130k-v2.csv", index_col=0)
```

将DataFrame写入csv文件：
```python
animals.to_csv("cows_and_goats.csv")
```

## Indexing, Selecting & Assigning

如果reviews这个DataFrame中包含列名"country"，那么可以通过`reviews.country`或`reviews['country']`来访问这一列。

### Indexing in pandas

pandas有自己的访问数据的方式：`loc`和`iloc`。

#### Index-based selection

可以用`iloc`这样访问第一行的数据：

```python
reviews.iloc[0] 
```
可以这样检索第一列的数据：
```python
reviews.iloc[:, 0] # DataFrame.iloc[行, 列]，行和列都可以是值或区间
```

在python中`:`代表全部，在字符串分割的时候，`s[:]`即`s[0:len(s)]`，在这里也可以这样使用，比如获取第0列，前3行的数据：

```python
reviews.iloc[:3, 0]
reviews.iloc[[0, 1, 2], 0] # 和上面一行是同样的效果
```

#### Label-based selection

`loc`遵循以基于lable的选择，比如可以通过`reviews.loc[0, 'country']`来访问'country'的首行位置的数据。

iloc把DataFrame看作一个二维矩阵，通过各种方式来获取对应位置的数据，loc更像把DataFrame看作Excel的表，可以通过lable来选择数据。

```python
reviews.loc[:, ['taster_name', 'taster_twitter_handle', 'points']]
```

#### Choosing between `loc` and `iloc`

`0:10`在`loc`中表示$0,1,...,10$（闭区间），而在`iloc`中表示$0,1,...,9$（左闭右开）。

比如第3列的列名是"Apples"，可以`DataFrame.iloc[:, 2]`来访问这一列的数据，也可以使用`DataFrame.loc['Apples']`，显然后者更直观。

### Conditional selection


```python
>>> reviews.country == 'Italy'
0          True
1         False
          ...  
129969    False
129970    False
Name: country, Length: 129971, dtype: bool
```

可以通过运算符构造条件筛选出想要的数据：

```python
# 筛选国家是'Italy'的数据
reviews.loc[reviews.country == 'Italy']
# 筛选国家是'Italy' 并且 points >= 90 的数据
reviews.loc[(reviews.country == 'Italy') & (reviews.points >= 90)]
# 筛选国家是'Italy' 或 points >= 90 的数据
reviews.loc[(reviews.country == 'Italy') | (reviews.points >= 90)]
```

`isin`类似python的`is in`，筛选country为'Italy'或'France'的数据可以：
```python
reviews.loc[reviews.country.isin(['Italy', 'France'])]
```

`isnull`和`notnull`用来判断是否为`NaN`： `reviews.loc[reviews.price.notnull()]`

## Assigning data

DataFrame也支持更改表中的数值：

```python
>>> reviews['critic'] = 'everyone'
>>> reviews['critic']
0         everyone
1         everyone
            ...   
129969    everyone
129970    everyone
Name: critic, Length: 129971, dtype: object
>>> reviews['index_backwards'] = range(len(reviews), 0, -1)
>>> reviews['index_backwards']
0         129971
1         129970
           ...  
129969         2
129970         1
Name: index_backwards, Length: 129971, dtype: int64
```

## Summary Functions and Maps

### Summary functions

pandas提供了一些汇总函数，比如之前提到过的`describe()`，DataFrame可以直接调用：`reviews.points.describe()`。

`describe()`对类型敏感，对于不同的数据类型，也会返回不同的结果。对于数字类型的数据，调用`describe()`会显示`mean`等信息，也可以直接使用`reviews.points.mean()`获取。


```python
reviews.taster_name.unique() # 不重复的输出全部出现过的 taster_name值
reviews.taster_name.value_counts() # 输出各个taster_name值对应的出现次数
```


如果想要获取这些分数和平均值的差距，可以使用`map()`，返回这一列Series，不会覆盖原来的值：
```python
review_points_mean = reviews.points.mean()
reviews.points.map(lambda p: p - review_points_mean)
```

如果想获取整个DataFrame，可以使用`apply()`，也不会覆盖原来的值：

```python
def remean_points(row):
    row.points = row.points - review_points_mean
    return row

reviews.apply(remean_points, axis='columns')
```
还可以有更快的方法：

```python
review_points_mean = reviews.points.mean()
reviews.points - review_points_mean
```
这样直接用一个数值和Series进行操作，就像在python中直接用数字和list运算，显然在python里是不允许的，但是pandas会知道将Series的每一个值和这个数操作，而且速度比`map`和`apply`更快，但是`map`和`apply`更灵活，可以做更高级的事情。

计算"tropical"和"fruity"在`description`中出现的次数：
```python
n_trop = reviews.description.map(lambda desc: "tropical" in desc).sum()
n_fruity = reviews.description.map(lambda desc: "fruity" in desc).sum()
descriptor_counts = pd.Series([n_trop, n_fruity], index=['tropical', 'fruity'])
```

## Grouping and Sorting

### Groupwise analysis

分组可以把某一列值相同的数据合为一组，然后我们可以获取这些组的各种信息：

```python
# points相同的分别分组，然后统计这些分组中成员的数量
>>> reviews.groupby('points').points.count()
points
80     397 # 得分 80 的，有 397 条
81     692
      ... 
99      33
100     19
Name: points, Length: 21, dtype: int64

# points相同的分别分组，然后获取每组的最低价格
>>> reviews.groupby('points').price.min()
points
80      5.0 # 80分的，最低可以以5.0的价格买到
81      5.0
       ... 
99     44.0
100    80.0
Name: price, Length: 21, dtype: float64

# 获取每个酒厂的第一条数据的title
>>> reviews.groupby('winery').apply(lambda df: df.title.iloc[0])

# 获取每个国家和省份的评分最高的酒，`idxmax()`可以返回最大值的下标。
>>> reviews.groupby(['country', 'province']).apply(lambda df: df.loc[df.points.idxmax()])
```

### Multi-indexes

groupby有时候会用到多索引`MultiIndex`，可以用`reset_index()`把它转换成常规的索引。如果想要获取多列值，需要使用`agg([])`
```python
>>> countries_reviewed = reviews.groupby(['country', 'province']).description.agg([len])
>>> mi = countries_reviewed.index
>>> type(mi)
pandas.core.indexes.multi.MultiIndex

>>> countries_reviewed.reset_index()
```

### Sorting

`sort_values()`默认是升序排序，可以更改参数`ascending=False`来使其降序排序，

```python
countries_reviewed = countries_reviewed.reset_index()
countries_reviewed.sort_values(by='len') # 按值排序

countries_reviewed.sort_index()          # 按index排序

# 以多个key排序，country为主键，country相同的时候内部按len排序
countries_reviewed.sort_values(by=['country', 'len'])
```

## Data Types and Missing Values

### Dtypes

DataFrame或Series中某一列的数据类型（data type）称为 **Dtype**。
```python
>>> reviews.price.dtype  # 返回 price 这一列的 Dtype
dtype('float64')
>>> reviews.dtypes       # 返回每一列的Dtype
country        object
description    object
                ...  
variety        object
winery         object
Length: 13, dtype: object
```

使用`astype()`函数可以将一种类型的列转换为另一种类型：
```python
>>> reviews.points.astype('float64')
0         87.0
1         87.0
          ... 
129969    90.0
129970    90.0
Name: points, Length: 129971, dtype: float64
```
index也有自己的Dtype：`reviews.index.dtype`（dtype('int64')）

### Missing data

缺失值会自动被赋值`NaN`，它的Dtype始终是'float64'。pandas也提供了一些函数来用NaN筛选数据，比如`pd.isnull()`和`pd.notnull()`：
```python
reviews[pd.isnull(reviews.country)] # 筛选 country 值为 NaN 的数据
```

`fillna()`可以直接用某些值 比如"Unknown"替换`NaN`：
```python
reviews.region_2.fillna("Unknown")
```

`replace()`函数可以把某列的"@kerinokeefe"替换成"@kerino"：
```python
reviews.taster_twitter_handle.replace("@kerinokeefe", "@kerino")
```

## Renaming and Combining

### Renaming

`rename()`可以用来修改列名或索引名，下面这个例子是：
```python
# 将列名中的'points'重命名为 'score'
reviews.rename(columns={'points': 'score'})

# 将索引中的 0 重命名为 'firstEntry'，1 重命名为 'secondEntry'
reviews.rename(index={0: 'firstEntry', 1: 'secondEntry'})
```
行（rows）和列（columns）的名字也是可以更改的：
```python
reviews.rename_axis("awines", axis='rows').rename_axis("fields", axis='columns')
```

### Combining

pandas有三种方法用来组合DataFrame（Series），`concat()`、`join()`和`merge()`。

```python
canadian_youtube = pd.read_csv("../input/youtube-new/CAvideos.csv")
british_youtube = pd.read_csv("../input/youtube-new/GBvideos.csv")

pd.concat([canadian_youtube, british_youtube])
```

就复杂性而言，最中间的组合器是`join()`，`join()`允许组合具有共同索引的不同`DataFrame`对象。 例如，要合并恰好在同一天在加拿大和英国流行的视频，我们可以执行以下操作：

```python
left = canadian_youtube.set_index(['title', 'trending_date'])
right = british_youtube.set_index(['title', 'trending_date'])

left.join(right, lsuffix='_CAN', rsuffix='_UK')
```
`lsuffix`和`rsuffix`是分别给left和right这两个DataFrame的列名加后缀的，因为这两个DataFrame中含有相同的列名，所以加上列名来避免冲突，如果已经提前为这两个DataFrame重命名过，保证没有列名的冲突，就可以不用设置这两个参数。

