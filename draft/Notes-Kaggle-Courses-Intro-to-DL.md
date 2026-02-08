---
title: "Notes: Kaggle Courses - Intro to DL & Computer Vision"
date: 2022-03-12 16:23:00
category: "Notes"
math: true
tags: ["Notes", "Kaggle", "DeepLearning", "Computer Vision"]
---

# Intro to Deep Learning

## A Single Neuron

### The Linear Unit

下面是一个**neuron**（或称**unit**）的示意图，`x`是输入；`w`是x的权重**weight**；`b`是**bias**，是一种特殊的权重，没有和bias相关的输入数据，它可以独立于输入修改输出。神经网络通过修改权重来“learn”。

`y`是这个神经元输出的值，$y=wx+b$，刚好是一个直线的方程，w是斜率，b是在y轴上的截距。

![The Linear Unit: 𝑦=𝑤𝑥+𝑏](/blog/Notes-Kaggle-Courses-Intro-to-DL/001.png)


### Example - The Linear Unit as a Model

单个神经元是通常只会在更大的网络中发挥作用，单神经元模型是线性模型。当$w=2.5, b=90$时，这个线性模型可以用来反应糖`'sugars'`和卡路里`'calories'`的关系：

![*Computing with the linear unit.*](/blog/Notes-Kaggle-Courses-Intro-to-DL/002.png)

### Multiple Inputs

对于多个输入，也是这样将每个输入乘以权重，并把它们相加。下面这个对应的公式为：$y=w_{0} x_{0}+w_{1} x_{1}+w_{2} x_{2}+b.$
![A linear unit with three inputs.](/blog/Notes-Kaggle-Courses-Intro-to-DL/003.png)

### Linear Units in Keras

在Keras中创建模型最简单的方法是使用`keras.Sequential`，下面这个示例表示一个线性模型，可以输入3个特征（'sugars', 'fiber', 'protein'），并且只有一个输出：'calories'。

```python
from tensorflow import keras
from tensorflow.keras import layers

# Create a network with 1 linear unit
model = keras.Sequential([
    layers.Dense(units=1, input_shape=[3])
])
```
第一个参数units定义输出的个数，input_shape告诉Keras输入特征的数量。目前只需要用到`input_shape=[num_columns]`，input_shape还可以支持使用更复杂的数据：`[height, width, channels]`。

`Tensors`是TensorFlow版本的numpy数组，并且做了一些使它更适合用于机器学习的改变，Tensors与GPU/TPU加速器兼容，而TPU就是专为Tensors而设计的。在Keras内部，使用Tensors表示神经网络的权重。

`model.weights`可以用来查看权重，在训练开始前，权重都会被初始化为随机值。

## Deep Neural Networks

### Layers

神经网络会将神经元组成**层（layers）**，合并有相同的输入的线性神经元，就得到了一个**稠密层（dense layer）**
![A dense layer of two linear units receiving two inputs and a bias.](/blog/Notes-Kaggle-Courses-Intro-to-DL/004.png)

### The Activation Function

两个中间没有其他东西的稠密层，效果并不会比一个稠密层的效果好多少，“稠密层本身不能带我们离开线和面的世界”，我们需要的是非线性（nonlinear），需要激活函数（activation function）。

![没有激活函数，模型只能学习线性关系，为了拟合曲线，需要使用激活函数](/blog/Notes-Kaggle-Courses-Intro-to-DL/005.png)

激活函数就是应用于每一层输出的函数，最常见的是*rectifier*函数$max(0,x).$

![image](/blog/Notes-Kaggle-Courses-Intro-to-DL/006.png)

把rectifier应用到一个线性单元上时，就得到了**rectified linear unit**，或简称**ReLU**。这样这个线性单元的输出就是$max(0,w\cdot x+b)$

![image](/blog/Notes-Kaggle-Courses-Intro-to-DL/007.png)

### Stacking Dense Layers

堆叠层来获得复杂的数据转换：
![A stack of dense layers makes a "fully-connected" network.](/blog/Notes-Kaggle-Courses-Intro-to-DL/008.png)

输出层之前的层有时被称为**隐藏层（hidden）**，因为我们没有直接看到它们的输出。上图在输出之前使用了一个线性单元，而不是激活函数，这样做使这个模型适用于回归任务，在分类任务中，可能要在这里使用激活函数。

#### Building Sequential Models

我们将用`Sequential`模型来连接一系列的层，建立上图的模型，第一次获得输入，最后一层产生输出
```python
from tensorflow import keras
from tensorflow.keras import layers

model = keras.Sequential([
    # ReLU 隐藏层
    layers.Dense(units=4, activation='relu', input_shape=[2]), # 输入
    layers.Dense(units=3, activation='relu'),
    # 线性输出层
    layers.Dense(units=1),
])
```
一定要把所有的图层放在一个列表中，比如`[layer，layer，layer，...]`。要添加激活函数层，只要设置`activation`参数即可，比如ReLU：`activation='relu'`


## Stochastic Gradient Descent

### Introduction

前面两节讲了如何构建全连接的网络（fully-connected networks），新创建的网络中的权重都是随机的，这一节就开始介绍如何训练神经网络。

训练模型中每条数据需要输入一些特征（features）和一个期望的输出目标（target），训练的过程会调整权重，使网络可以通过输入的特征计算出期望的目标。

除了训练数据，还需要：
- “损失函数”，用来衡量网络预测结果的好坏。
- “优化器”，可以告诉网络如何改变其权重。

### The Loss Function

**损失函数**（loss function）测量target真实值和模型预测值之间的差异。不同的问题需要使用不同的损失函数，比如**回归问题**（regression problems）常用的损失函数就是平均绝对误差**MAE**（mean absolute error），MAE通过差的绝对值`abs(y_true-y_pred)`测量预测值`y_pred`与真实目标`y_true`的差异。
数据集上的总MAE，是所有这些差的绝对值的平均值。

![平均绝对误差是拟合曲线和数据点之间的平均长度](/blog/Notes-Kaggle-Courses-Intro-to-DL/009.png)

除了MAE之外，回归问题还有其他的损失函数：均方误差（mean-squared error，MSE）或Huber损失（Huber loss），它们都可以在Keras中使用。
在训练期间，模型将使用损失函数作为指导，以找到正确的权重值（loss越小越好）。换句话说，损失函数告诉网络它的目标。

### The Optimizer - Stochastic Gradient Descent

> 随机梯度下降，这里的“随机”用的是stochastic，而非random，查了一下维基百科：

> Although stochasticity and randomness are distinct in that the former refers to a modeling approach and the latter refers to phenomena themselves, these two terms are often used synonymously. Furthermore, in probability theory, the formal concept of a stochastic process is also referred to as a random process.

> stochastic 偏向指建模方法，random 偏向指现象本身，很多时候这两个词是同义的。

**优化器**（optimizer）是一种调整权重来使loss最小化的算法。深度学习中使用的所有优化器算法都属于一个叫做随机梯度下降的家族，训练网络的过程就是一次次迭代下面的算法：

1. 采集一些训练数据，通过网络进行预测
2. 测量预测值和真实值之间的损失
3. 最后，调整权重使loss更小

<img src="/blog/Notes-Kaggle-Courses-Intro-to-DL/010.gif">
<p class="image-caption">使用随机梯度下降的神经网络</p>

每个迭代的训练数据样本称为一个**minibatch**（或称**batch**），而一轮完整的训练数据称为一个**epoch**。你训练的次数是网络看到每个训练示例的次数。网络看到每个训练示例的次数，就是训练的轮数。

上面的动画显示了线性模型在使用SGD进行训练，淡红色的点是整个数据集，变化的实心红点表示minibatch，每次SGD看到一个新的minibatch，它都会将权重（`w`斜率，`b`y轴截距）移向batch的正确值，经过一轮又一轮的batch，直线最终会收敛到最佳状态，可以看到，权重越接近真实值，loss就越小。

### Learning Rate and Batch Size

可以注意到直线每次会在batch的方向上发生一个小的移动，这个移动变化的大小取决于**学习率**（learning rate），学习率越小，在逼近正确值的过程就越长。

学习率（Learning Rate）和batch的大小（Batch Size）是对SGD训练进度影响最大的两个参数。它们之间的相互作用往往很微妙，对这些参数的正确选择并不总是显而易见的。（我们将在练习中探讨这些影响）

幸运的是，对于大多数工作来说，没有必要进行广泛的超参数搜索以获得满意的结果。Adam是一种SGD算法，具有自适应学习率，使其适用于大多数问题，而无需任何参数调整（从某种意义上说，它是“自调整”）。Adam是一个伟大的通用优化器。

### Adding the Loss and Optimizer

定义模型后，可以使用模型的`compile`方法添加损失函数和优化器：

```python
model.compile(
    optimizer="adam",
    loss="mae",
)
```

只需要一个字符串就可以指定loss和optimizer；也可以通过Keras API直接访问这些参数——例如想要优化参数——但对我们来说，默认值就可以正常工作。

梯度（**gradient**）是一个向量，告诉我们权重应该朝哪个方向移动，也就是说它告诉我们如何改变重量使损失变化最快，我们称过程为梯度下降（**descent**），是因为它使用梯度将损失曲线下降到最小值，随机（**stochastic**）是指每次选取的minibatches是从训练数据中随机选取的随机样例。SGD即Stochastic Gradient Descent。

```python
from tensorflow import keras
from tensorflow.keras import layers

model = keras.Sequential([
    layers.Dense(512, activation='relu', input_shape=[11]),
    layers.Dense(512, activation='relu'),
    layers.Dense(512, activation='relu'),
    layers.Dense(1),
])

# 给模型设置优化器和损失函数
model.compile(
    optimizer='adam',
    loss='mae',
)

# 每轮给模型 256 行数据，这样训练 10 轮
history = model.fit(
    X_train, y_train,
    validation_data=(X_valid, y_valid),
    batch_size=256,
    epochs=10,
)
```

在每一轮的训练后，都会输出当前的loss，并且训练过程中的loss都会被保存起来，所以我们可以用它们作图来更直观的看出loss的变化：

```python
import pandas as pd

# convert the training history to a dataframe
history_df = pd.DataFrame(history.history)
# use Pandas native plot method
history_df['loss'].plot()
```

![](/blog/Notes-Kaggle-Courses-Intro-to-DL/011.png)

loss的变化曲线逐渐变得趋于水平了，就说明模型已经学会了它能学会的一切，所以没有必要让它进行更多的迭代，如果想要优化loss，更应该做的是调整模型。

## Overfitting and Underfitting

### Interpreting the Learning Curves

模型得到的数据是由**信息**（signal）和**噪声**（noise）组成的，我们希望它从signal中学习到模式，这样可以使其在预测过程中表现良好，噪声是只在训练数据中正确的案例。

下图绘制了在训练数据上和在测试数据上的loss情况，这些曲线我们称之为**学习曲线**（learning curves），为了有效的训练深度学习模型，我们需要能够解释它们。

![The validation loss gives an estimate of the expected error on unseen data.](/blog/Notes-Kaggle-Courses-Intro-to-DL/012.png)

在模型学习signal和noise的过程中，训练loss会逐渐下降，但只有模型学习到signal时，验证loss才会降低。在学习signal的过程中，两条曲线都会下降，但是如果模型学习了noise，那么两条曲线之间就会出现空隙（gap），这个空隙的大小，可以反应模型学到了多少noise。理想情况下我们希望模型只学习signal不学习noise，但这几乎是不可能的，只能以学习到很多的noise为代价，让模型尽可能多的学习到signal，从上图可以看出，当出现了某一点后，验证loss会逐渐上升。

![Underfitting and overfitting.](/blog/Notes-Kaggle-Courses-Intro-to-DL/013.png)


在训练模型时可能会出现两个问题：
1. signal不足或噪声过大。未充分拟合训练集 是指由于模型没有学习到足够的signal，导致loss没有尽可能低。
2. 过度拟合训练集是指由于模型学习了太多的噪声，导致loss没有尽可能低。

训练深度学习模型的诀窍是在两者之间找到最佳平衡，我们将研究几种从训练数据中获取更多signal的方法，同时减少噪声。

### Capacity

模型的容量是指它能够学习的模式的大小和复杂性，对于神经网络来说，这在很大程度上取决于它有多少神经元以及它们如何连接在一起。如果网络似乎不适合数据，应该尝试增加其容量。

可以通过使网络更宽（将更多神经元添加到现有层）或使其更深（添加更多层）来增加网络的容量。更宽的网络更容易学习更多的线性关系，而更深的网络更喜欢非线性关系。哪个更好取决于数据集。

```python
model = keras.Sequential([
    layers.Dense(16, activation='relu'),
    layers.Dense(1),
])

wider = keras.Sequential([
    layers.Dense(32, activation='relu'),
    layers.Dense(1),
])

deeper = keras.Sequential([
    layers.Dense(16, activation='relu'),
    layers.Dense(16, activation='relu'),
    layers.Dense(1),
])
```

### Early Stopping

当模型学习到很多噪声时，验证损失可能会在训练期间开始增加，为了防止这种情况，只要验证loss似乎不再减少，我们就可以停止训练。以这种方式中断训练被称为**提前停止**（Early Stopping）。

![让模型在验证loss最小的位置停止](/blog/Notes-Kaggle-Courses-Intro-to-DL/014.png)

一旦检测到了验证loss再次上升，就可以将权重重置回之前loss最小值的位置，确保了模型不会继续过拟合。

### Adding Early Stopping

在Keras中，我们通过**回调**（callback）在训练中提前停止，回调函数是一个在网络运行时需要经常运行的函数。提前停止回调将在每个epoch之后运行。（Keras预先定义了各种有用的回调，也可以定义自己的回调。）

```python
from tensorflow.keras.callbacks import EarlyStopping

early_stopping = EarlyStopping(
    min_delta=0.001, # minimium amount of change to count as an improvement
    patience=20, # 20个
    restore_best_weights=True,
)
```
如果在过去20个epochs中，验证loss没有改善0.001，那么停止训练，保留找到的最佳模型。


### Example - Train a Model with Early Stopping

```python
from tensorflow import keras
from tensorflow.keras import layers, callbacks

early_stopping = callbacks.EarlyStopping(
    min_delta=0.001, # minimium amount of change to count as an improvement
    patience=20, # how many epochs to wait before stopping
    restore_best_weights=True,
)

model = keras.Sequential([
    layers.Dense(512, activation='relu', input_shape=[11]),
    layers.Dense(512, activation='relu'),
    layers.Dense(512, activation='relu'),
    layers.Dense(1),
])
model.compile(
    optimizer='adam',
    loss='mae',
)
history = model.fit(
    X_train, y_train,
    validation_data=(X_valid, y_valid),
    batch_size=256,
    epochs=500,
    callbacks=[early_stopping], # put your callbacks in a list
    verbose=0,  # turn off training log
)

history_df = pd.DataFrame(history.history)
history_df.loc[:, ['loss', 'val_loss']].plot();
print("Minimum validation loss: {}".format(history_df['val_loss'].min()))
```

## Dropout and Batch Normalization

keras有几十中layers，可以在 [Keras docs](https://www.tensorflow.org/api_docs/python/tf/keras/layers/) 中查看示例。这一节将介绍两种特殊的layer，它们本身不包含神经元。

### Dropout

Dropout可以帮助修正overfitting。

前面讲过了数据的欠拟合和过拟合，出现了过拟合的情况，是因为网络模型学习了训练数据中的虚假的模式（噪声的模式），模型为了学习到这个模式 通常会依赖非常特定的权重组合，所以这种权重的组合才实现出的模式，往往是很脆弱的，移除一个就会瓦解。

Dropout就是在训练的每一步都随机删除一层输入单元的一小部分，这使得网络更难从训练数据中学习这些虚假模式。相反，它必须寻找广泛的、一般的模式，其权重模式往往更稳健。

![Here, 50% dropout has been added between the two hidden layers.](/blog/Notes-Kaggle-Courses-Intro-to-DL/015.gif)

### Adding Dropout

在Keras中，dropout率参数`rate`定义了要关闭的输入单元的百分比。将`Dropout layer`放在要应用Dropout的层之前：
```python
keras.Sequential([
    # ...
    layers.Dropout(rate=0.3), # apply 30% dropout to the next layer
    layers.Dense(16),
    # ...
])
```

### Batch Normalization

"batch normalization"或称"batchnorm"这个特殊层有助于纠正缓慢或不稳定的训练。在神经网络中通常需要将所有的数据放在一个通用的尺度上，可以使用scikit learn的StandardScaler或MinMaxScaler之类的工具，这是因为SGD根据数据产生的激活量按比例改变网络中的权重，训练中的数值大小范围不一样可能会导致不稳定的训练。

可以在数据进入网络之前对其进行规范化（normalize），但是更好的操作是在网络的内部对数据进行规范化，**batch normalization layer**就是用来对网络中的数据进行规范化操作的，它会用其自身的**平均值**和**标准差**对batch进行标准化，然后用两个可训练的重缩放参数（trainable rescaling parameters）将数据放在一个新的尺度上。

使用batchnorm的模型往往需要较少的时间完成训练，也可以解决可能导致训练“停滞”的各种问题，所以可以考虑在模型中添加batchnorm。

### Adding Batch Normalization

batchnorm可以放在相对其他层的各种位置上，如果用它作为网络的第一层，就起到了一个代替预处理时对数据进行标准化的操作，类似Sci-Kit Learn的 `StandardScaler`，也可以放在某一层之后：
```python
layers.Dense(16, activation='relu'),
layers.BatchNormalization(),
```
或在某层和它的激活函数之间：
```python
layers.Dense(16),
layers.BatchNormalization(),
layers.Activation('relu'),
```

### Example - Using Dropout and Batch Normalization

如果模型中使用了dropout，就应该在层中添加更多的单元，因为每次都会被随机抛弃一部分不参与的单元。

```python
from tensorflow import keras
from tensorflow.keras import layers

model = keras.Sequential([
    layers.Dense(1024, activation='relu', input_shape=[11]),
    layers.Dropout(0.3),
    layers.BatchNormalization(),
    layers.Dense(1024, activation='relu'),
    layers.Dropout(0.3),
    layers.BatchNormalization(),
    layers.Dense(1024, activation='relu'),
    layers.Dropout(0.3),
    layers.BatchNormalization(),
    layers.Dense(1),
])

model.compile(
    optimizer='adam',
    loss='mae',
)

history = model.fit(
    X_train, y_train,
    validation_data=(X_valid, y_valid),
    batch_size=256,
    epochs=100,
    verbose=0,
)

# Show the learning curves
history_df = pd.DataFrame(history.history)
history_df.loc[:, ['loss', 'val_loss']].plot();
```

## Binary Classification

### Introduction

之前的部分在介绍用深度学习解决回归问题，这一节介绍用深度学习解决分类问题。

### Binary Classification

二分类问题是指分成两类的问题，比如用"Yes"/"No"来回答的问题。我们需要给数据**class label**：0 或 1，数字标签是神经网络模型可以使用的数据形式。

### Accuracy and Cross-Entropy

**准确性**（Accuracy）是衡量分类问题成功与否的众多指标之一。accuracy是正确预测与总预测的比率：`accuracy = number_correct / total`。一个总是正确预测的模型的准确度得分为`1.0`。在所有其他条件相同的情况下，每当数据集中的类以大约相同的频率出现时，准确度是一个合理的指标。

accuracy（以及大多数其他分类指标）的问题在于，它不能用作损失函数。SGD需要一个平稳变化的损失函数，但精度，作为计数的比率，在“跳跃”中变化。因此，我们必须选择一个替代品作为损失函数。这个替代品是交叉熵函数（cross-entropy function）。

现在，回想一下损失函数定义了训练期间网络的目标。通过回归，我们的目标是最小化预期结果和预测结果之间的距离。我们选择了MAE来测量这个距离。

对于分类，我们想要的是概率之间的距离，这就是交叉熵提供的。**Cross-entropy**是一种度量从一个概率分布到另一个概率分布的距离的方法。


![Cross-entropy penalizes incorrect probability predictions.](/blog/Notes-Kaggle-Courses-Intro-to-DL/016.png)

我们希望我们的网络以`1.0`的概率预测正确的班级。预测概率离`1.0`越远，交叉熵损失越大。

我们使用交叉熵的技术原因有点微妙，但从这一节中我们要了解的主要内容是：使用交叉熵来进行分类损失；你可能关心的其他指标（如准确性）也会随之提高。

### Making Probabilities with the Sigmoid Function

交叉熵和精度函数都需要概率作为输入，即0到1之间的数字。为了将密集层产生的实值输出转化为概率，我们附加了一种新的激活函数，即sigmoid激活函数。

![The sigmoid function maps real numbers into the interval [0,1].](/blog/Notes-Kaggle-Courses-Intro-to-DL/017.png)

为了得到最终的类预测，我们定义了一个阈值概率。通常这将是0.5，因此四舍五入将为我们提供正确的类别：低于0.5表示标签为0的类别，0.5或以上表示标签为1的类别。0.5阈值是Keras默认使用的精度指标。

### Example - Binary Classification

除了最后一层用了“sigmoid”激活，它用来产生类概率，其他部分和回归任务一样。

```python
from tensorflow import keras
from tensorflow.keras import layers

model = keras.Sequential([
    layers.Dense(4, activation='relu', input_shape=[33]),
    layers.Dense(4, activation='relu'),    
    layers.Dense(1, activation='sigmoid'),
])

model.compile(
    optimizer='adam',              # Adam也适用于分类问题
    loss='binary_crossentropy',    # 损失函数为 交叉熵函数
    metrics=['binary_accuracy'],
)

# 提前停止 回调函数
early_stopping = keras.callbacks.EarlyStopping(
    patience=10,
    min_delta=0.001,
    restore_best_weights=True,
)

history = model.fit(
    X_train, y_train,
    validation_data=(X_valid, y_valid),
    batch_size=512,
    epochs=1000,
    callbacks=[early_stopping],
    verbose=0, # hide the output because we have so many epochs
)

history_df = pd.DataFrame(history.history)
# Start the plot at epoch 5
history_df.loc[5:, ['loss', 'val_loss']].plot()
history_df.loc[5:, ['binary_accuracy', 'val_binary_accuracy']].plot()

print(("Best Validation Loss: {:0.4f}" +\
      "\nBest Validation Accuracy: {:0.4f}")\
      .format(history_df['val_loss'].min(), 
              history_df['val_binary_accuracy'].max()))

```

```
Best Validation Loss: 0.5482
Best Validation Accuracy: 0.7619
```

<img src="/blog/Notes-Kaggle-Courses-Intro-to-DL/018.png">


<img src="/blog/Notes-Kaggle-Courses-Intro-to-DL/019.png">


## Detecting the Higgs Boson With TPUs

这是属于Intro to Deep Learning的一节Bonus Lesson，介绍如何使用TPU的。

```python
# TensorFlow
import tensorflow as tf
print("Tensorflow version " + tf.__version__)

# Detect and init the TPU
try: # detect TPUs
    tpu = tf.distribute.cluster_resolver.TPUClusterResolver.connect() # TPU detection
    strategy = tf.distribute.TPUStrategy(tpu)
except ValueError: # detect GPUs
    strategy = tf.distribute.get_strategy() # default strategy that works on CPU and single GPU
print("Number of accelerators: ", strategy.num_replicas_in_sync)
```

# Computer Vision

## The Convolutional Classifier

### Introduction

卷积神经网络（convolutional neural networks）是最擅长理解图像的神经网络，我们称之为convent或CNN。卷积是一种数学运算，它使网络的各层具有独特的结构。

### The Convolutional Classifier

用于图像分类的convnet由两部分组成：**convolutional base** 和 **dense head**。

<img src="/blog/Notes-Kaggle-Courses-Intro-to-DL/020.png">

- Base用于**从图像中提取特征**，它主要由执行卷积运算的层组成，但通常也包括其他类型的层。
- Head用于**确定图像的类别**，它主要由致密层构成，但也可能包括其他层，如脱落层。

特征可以是线条、颜色、纹理、形状、图案，也可以是一些复杂的组合。

<img src="/blog/Notes-Kaggle-Courses-Intro-to-DL/021.png">

### Training the Classifier

训练期间网络的目标是学习两件事：
1. 要从图像中提取哪些特征 (base)，
2. 哪一类与哪些特征相匹配 (head)。

如今，convnet很少从零开始训练。更常见的情况是，我们重用预训练模型的基础。然后，我们在预先训练好的Base加上一个未经训练的Head。换句话说，我们重用网络中已经学会做*提取特征*的层，并附加一些新的层来学习*分类*。

<div align="center"><img style="width:50%" src="/blog/Notes-Kaggle-Courses-Intro-to-DL/022.png"></div>

因为头部通常只有几个密集的层，所以可以从相对较少的数据中创建非常精确的分类器。

**迁移学习**就是一种重用预先训练好的模型的技术。它非常有效，现在几乎所有的图像分类器都会使用它。


### Example - Train a Convnet Classifier

我们将创建一个用于分类汽车和卡车的分类器，数据集是大约10000张图片，其中汽车和卡车的几乎各占一半。

#### Step 1 - Load Data

```python
# 导入一些包
import os, warnings
import matplotlib.pyplot as plt
from matplotlib import gridspec

import numpy as np
import tensorflow as tf
from tensorflow.keras.preprocessing import image_dataset_from_directory

# 设置固定的种子，来保证可复现性
def set_seed(seed=31415):
    np.random.seed(seed)
    tf.random.set_seed(seed)
    os.environ['PYTHONHASHSEED'] = str(seed)
    os.environ['TF_DETERMINISTIC_OPS'] = '1'
set_seed(31415)

# 设置 Matplotlib 的默认值
plt.rc('figure', autolayout=True)
plt.rc('axes', labelweight='bold', labelsize='large',
       titleweight='bold', titlesize=18, titlepad=10)
plt.rc('image', cmap='magma')
warnings.filterwarnings("ignore") # to clean up output cells

# Load training and validation sets
ds_train_ = image_dataset_from_directory(
    '../input/car-or-truck/train',  # 文件夹
    labels='inferred',
    label_mode='binary',
    image_size=[128, 128],          # 图片大小
    interpolation='nearest',
    batch_size=64,
    shuffle=True,
)
ds_valid_ = image_dataset_from_directory(
    '../input/car-or-truck/valid',
    labels='inferred',
    label_mode='binary',
    image_size=[128, 128],
    interpolation='nearest',
    batch_size=64,
    shuffle=False,
)

# Data Pipeline
def convert_to_float(image, label):
    image = tf.image.convert_image_dtype(image, dtype=tf.float32)
    return image, label

AUTOTUNE = tf.data.experimental.AUTOTUNE
ds_train = (
    ds_train_
    .map(convert_to_float)
    .cache()
    .prefetch(buffer_size=AUTOTUNE)
)
ds_valid = (
    ds_valid_
    .map(convert_to_float)
    .cache()
    .prefetch(buffer_size=AUTOTUNE)
)
```

#### Step 2 - Define Pretrained Base

最常用的预训练数据集是[ImageNet](http://image-net.org/about-overview)，这是一个包含多种自然图像的大型数据集。Keras在其 `applications`模块中包含在ImageNet上预训练的各种模型。我们将使用的预训练模型称为**VGG16**。

```python
pretrained_base = tf.keras.models.load_model(
    '../input/cv-course-models/cv-course-models/vgg16-pretrained-base',
)
pretrained_base.trainable = False
```

[VGG16](https://www.tensorflow.org/api_docs/python/tf/keras/applications/vgg16/VGG16)也可以这样直接调用：
```python
tf.keras.applications.vgg16.VGG16(
    include_top=True,
    weights='imagenet',
    input_tensor=None,
    input_shape=None,
    pooling=None,
    classes=1000,
    classifier_activation='softmax'
)
```

#### Step 3 - Attach Head

接下来连接分类器head。先用一个`Flatten`层，把前面二维的输出转化为一维来提供给后面的层。然后是一个隐藏层，最后一层（输出层）把输出转换为判断是`Truck`的概率分数。

```python
from tensorflow import keras
from tensorflow.keras import layers

model = keras.Sequential([
    pretrained_base,
    layers.Flatten(),
    layers.Dense(6, activation='relu'),
    layers.Dense(1, activation='sigmoid'),
])
```

#### Step 4 - Train

由于这是一个分成两类的问题，所以我们使用二进制版本的`crossentropy`和`accuracy`。

```python
model.compile(
    optimizer='adam',
    loss='binary_crossentropy',   # 损失函数
    metrics=['binary_accuracy'],  # 准确度评估
)

history = model.fit(
    ds_train,
    validation_data=ds_valid,
    epochs=30,
    verbose=0,
)
```

在训练神经网络模型时，最好检查loss和metric曲线，变化过程被存储在`history.history`中，可以这样把它们显示出来：

```python
import pandas as pd

history_frame = pd.DataFrame(history.history)
history_frame.loc[:, ['loss', 'val_loss']].plot()
history_frame.loc[:, ['binary_accuracy', 'val_binary_accuracy']].plot();
```
<img src="/blog/Notes-Kaggle-Courses-Intro-to-DL/023.png">

<img src="/blog/Notes-Kaggle-Courses-Intro-to-DL/024.png">

## Convolution and ReLU

前一节我们了解到卷积分类器有两部分：base和head，base从图像中提取特征，head使用这些特征对图像分类。


后面的几节教程会介绍base部分 最重要的两种类型的层，它们分别是：具有ReLU激活的卷积层 和 最大池化层。第5节教程将会介绍通过这些层的组合来进行特征提取（Base部分）。

这一节是关于卷积层和ReLU激活函数的。

### Feature Extraction

由base执行的特征提取包括三个基本操作：

1. 针对特定特征**过滤**（filter）图像（卷积）
2. 在过滤后的图像中**检测**（detect）该特征（ReLU）
3. **压缩**（condense）图像以增强特征（最大池化）

下图说明了这个过程，可以看到这三个操作是如何隔离原始图像的某些特定特征的（在本例中为水平线）。

<div align="center"><img style="width:50%" src="/blog/Notes-Kaggle-Courses-Intro-to-DL/025.jpg"></div>

通常网络会在一个图片上并行的提取，在一些现代的convnets中，最后一层产生1000多个独特的视觉特征也很多见。

### Filter with Convolution

卷积层执行滤波步骤,可以在Keras模型中定义一个卷积层：
```python
from tensorflow import keras
from tensorflow.keras import layers

model = keras.Sequential([
    layers.Conv2D(filters=64, kernel_size=3), # activation is None
    # More layers follow
])
```

我们可以通过观察这些参数与层的权重和激活的关系来理解这些参数。

#### Weights

convnet在训练期间学习的权重主要包含在其卷积层中，这些**权重**我们称之为核（kernels），我们可以将它们表示为小数组：

<div align="center"><img style="width:20%" src="/blog/Notes-Kaggle-Courses-Intro-to-DL/026.png"></div>

**kernel**通过扫描图像并产生像素值的加权和来运行。通过这种方式，内核将像偏振光透镜一样，强调或不强调某些信息模式。


<div align="center"><img style="width:30%" src="/blog/Notes-Kaggle-Courses-Intro-to-DL/027.png"></div>

Kernels定义了卷积层如何连接到后面的层，上图中的kernel将前一层的9个神经元的输出，加权求和得到一个值输入到了后面层的一个神经元。我们可以使用`kernel_size`来设置kernel的维度，大多数情况下，kernel的维数都是奇数，如`(3, 3)`，`(5, 5)`，因此只有一个像素位于中心，但这并不是必须的。

卷积层的kernel决定了它创建的特征类型，在训练期间，convent会尝试解决当前分类问题所需要的特征，这也意味着kernel的最佳取值。

### Activations

网络中的激活（activation），我们称之为特征映射（feature maps），它们是我们对图像应用过滤器时的结果；它们包含kernel提取的视觉特征。下面是一些kernel及其生成的特征映射：

<div align="center"><img style="width:80%" src="/blog/Notes-Kaggle-Courses-Intro-to-DL/028.png"></div>

从kernel中的数字的模式，可以看出它创建的特征映射的类型。通常，卷积在其输入中强调的内容将与内核中正数的形状相匹配。上面的左核和中核都将过滤水平形状。

使用filters参数，可以告诉卷积层希望它创建多少个特征贴图作为输出。

<!-- ### Detect with ReLU

<div align="center"><img style="width:40%" src="https://s1.ax1x.com/2022/03/27/qBmK7q.png"></div>


![](https://s1.ax1x.com/2022/03/27/qBmE9S.png)
![](https://s1.ax1x.com/2022/03/27/qBmkh8.png)
![](https://s1.ax1x.com/2022/03/27/qBmZcQ.png)
![](https://s1.ax1x.com/2022/03/27/qBmV1g.png)
![](https://s1.ax1x.com/2022/03/27/qBmFtf.png)
![](https://s1.ax1x.com/2022/03/27/qBmeXj.png)
![](https://s1.ax1x.com/2022/03/27/qBmuBn.png)
![](https://s1.ax1x.com/2022/03/27/qBmnns.png)
![](https://s1.ax1x.com/2022/03/27/qBmQA0.png)
![](https://s1.ax1x.com/2022/03/27/qBmlNV.png) -->

