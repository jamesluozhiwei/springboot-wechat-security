/*
 Navicat Premium Data Transfer

 Source Server         : server
 Source Server Type    : MySQL
 Source Server Version : 50726
 Source Host           : 39.108.86.73:3306
 Source Schema         : db_springboot_wechat_security

 Target Server Type    : MySQL
 Target Server Version : 50726
 File Encoding         : 65001

 Date: 22/08/2019 21:51:09
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for tb_group
-- ----------------------------
DROP TABLE IF EXISTS `tb_group`;
CREATE TABLE `tb_group`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `description` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '组描述',
  `name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '组名称',
  `status` int(11) NULL DEFAULT 1 COMMENT '状态：0&逻辑删除#1&正常',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for tb_group_role
-- ----------------------------
DROP TABLE IF EXISTS `tb_group_role`;
CREATE TABLE `tb_group_role`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `group_id` bigint(20) NULL DEFAULT 0 COMMENT '组id',
  `role_id` bigint(20) NULL DEFAULT 0 COMMENT '角色id',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `group_id`(`group_id`, `role_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for tb_group_user
-- ----------------------------
DROP TABLE IF EXISTS `tb_group_user`;
CREATE TABLE `tb_group_user`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `group_id` bigint(20) NULL DEFAULT 0 COMMENT '组id',
  `user_id` bigint(20) NULL DEFAULT 0 COMMENT '用户id',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `group_id`(`group_id`, `user_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 1 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Table structure for tb_permission
-- ----------------------------
DROP TABLE IF EXISTS `tb_permission`;
CREATE TABLE `tb_permission`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `description` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '权限描述',
  `name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '权限',
  `parent_id` bigint(20) NULL DEFAULT 0 COMMENT '父权限id',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `parent_id`(`parent_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of tb_permission
-- ----------------------------
INSERT INTO `tb_permission` VALUES (1, '管理员', 'admin', 0);

-- ----------------------------
-- Table structure for tb_role
-- ----------------------------
DROP TABLE IF EXISTS `tb_role`;
CREATE TABLE `tb_role`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `description` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '角色描述',
  `name` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '角色权限',
  `status` int(11) NULL DEFAULT 1 COMMENT '状态：0&逻辑删除#1&正常',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of tb_role
-- ----------------------------
INSERT INTO `tb_role` VALUES (1, '管理员', 'admin', 1);

-- ----------------------------
-- Table structure for tb_role_permission
-- ----------------------------
DROP TABLE IF EXISTS `tb_role_permission`;
CREATE TABLE `tb_role_permission`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `role_id` bigint(20) NULL DEFAULT 0 COMMENT '角色id',
  `permission_id` bigint(20) NULL DEFAULT 0 COMMENT '权限id',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `role_id`(`role_id`, `permission_id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of tb_role_permission
-- ----------------------------
INSERT INTO `tb_role_permission` VALUES (1, 1, 1);

-- ----------------------------
-- Table structure for tb_user_info
-- ----------------------------
DROP TABLE IF EXISTS `tb_user_info`;
CREATE TABLE `tb_user_info`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `nick_name` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '昵称',
  `avatar_url` varchar(256) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '头像',
  `gender` int(11) NULL DEFAULT 0 COMMENT '性别：0&未知#1&男#2&女',
  `openid` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '微信唯一标识',
  `phone` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '手机号码',
  `language` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '语言',
  `city` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '城市',
  `province` varchar(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT '省',
  `union_id` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT 'unionId',
  `session_key` varchar(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NULL DEFAULT '' COMMENT 'session key',
  `status` int(11) NULL DEFAULT 1 COMMENT '状态：0&逻辑删除#1&正常',
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `openid`(`openid`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of tb_user_info
-- ----------------------------
INSERT INTO `tb_user_info` VALUES (1, 'admin', '', 0, '', '', '', '', '', '', '', 1);

-- ----------------------------
-- Table structure for tb_user_role
-- ----------------------------
DROP TABLE IF EXISTS `tb_user_role`;
CREATE TABLE `tb_user_role`  (
  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `user_id` bigint(20) NULL DEFAULT 0 COMMENT '用户id',
  `role_id` bigint(20) NULL DEFAULT 0 COMMENT '角色id',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_general_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of tb_user_role
-- ----------------------------
INSERT INTO `tb_user_role` VALUES (1, 1, 1);

SET FOREIGN_KEY_CHECKS = 1;
