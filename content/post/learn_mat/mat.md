---
title: "线性代数学习笔记"
description: "一点思考"
date: 2025-12-17T00:00:00+08:00
image: mat_head.png
math: true
license: 
hidden: false
comments: true
draft: false
categories:
    - 随笔
tags:
    - 博客
    - 线性代数
---

### 矩阵对角化与换基的联系

对于一个向量 **$\alpha$**，其在基 **$A$** 下的表现形式为 **$A^{-1}\alpha$**。

那么将基变换至基 **$B$** 下，其变为 **$(B^{-1}A) \cdot A^{-1}\alpha \Rightarrow B^{-1}\alpha$**。

辅助矩阵为 **$P$**， **$P = B^{-1}A$**， **$B\cdot P=A$**。

据上，(基 **$A$** 下的) 线性变换 **$C$** 至 (基 **$B$** 下的) 线性变换 **$D$**：


$$
\begin{aligned}
v_{a}&=C\cdot u_{a}\\
P\cdot v_{b}&=C\cdot (P\cdot u_{b})\\
P^{-1}\cdot P\cdot v_{b}&=P^{-1}\cdot C\cdot P\cdot u_{b}\\
D &= P^{-1} C P
\end{aligned}
$$

可见，变换 **$C$** 与变换 **$D$** 在物理意义上相同，只是坐标系不同的表现形式。

那么，对于矩阵对角化 **$A = P^{-1}\Lambda P$**。

**$\Lambda$** 是特征值的对角矩阵，其基为特征向量组成的基 $P$，**$P$** 是列向量为特征向量的矩阵。

$A$ 的基是标准基 $E$。

(基 **$E$** 下的) 线性变换 **$A$** 至 (基 **$P$** 下的) 线性变换 **$\Lambda$**：

辅助矩阵为 **$D = P^{-1}E$**。

$$
\begin{aligned}
\Lambda &= D^{-1}AD\\
A &= D\Lambda D^{-1} = P^{-1}\Lambda P
\end{aligned}
$$
