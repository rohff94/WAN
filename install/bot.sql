-- phpMyAdmin SQL Dump
-- version 4.5.4.1deb2ubuntu2.1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: May 09, 2020 at 06:33 PM
-- Server version: 5.7.30-0ubuntu0.16.04.1
-- PHP Version: 7.0.33-0ubuntu0.16.04.14

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `bot`
--

-- --------------------------------------------------------

--
-- Table structure for table `AUTH`
--

CREATE TABLE `AUTH` (
  `id` int(11) NOT NULL,
  `id8port` int(10) NOT NULL,
  `user2name` varchar(64) DEFAULT NULL,
  `user2pass` varchar(64) DEFAULT NULL,
  `user2info` text,
  `ladate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `CIDR`
--

CREATE TABLE `CIDR` (
  `id` int(11) NOT NULL,
  `cidr` varchar(16) DEFAULT NULL,
  `cidr2ns` text,
  `cidr2live` text,
  `cidr2owner` text,
  `cidr2range` text,
  `ladate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `DOMAIN`
--

CREATE TABLE `DOMAIN` (
  `id` int(10) NOT NULL,
  `id8eth` int(10) UNSIGNED NOT NULL,
  `domain` varchar(128) DEFAULT NULL,
  `domain2ns` text,
  `domain2trace` text,
  `domain2dico` longtext,
  `domain2search` longtext,
  `domain2whois` text,
  `domain2asn` text,
  `domain2mail` longtext,
  `ladate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `ETH`
--

CREATE TABLE `ETH` (
  `id` int(10) UNSIGNED NOT NULL,
  `eth` varchar(64) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COMMENT='Interfaces des domaines';

-- --------------------------------------------------------

--
-- Table structure for table `IP`
--

CREATE TABLE `IP` (
  `id` int(10) NOT NULL,
  `id8domain` int(10) NOT NULL,
  `ip` varchar(40) NOT NULL,
  `ip2host` varchar(256) DEFAULT NULL,
  `ip2rootkit` tinyint(1) UNSIGNED DEFAULT '0',
  `ip2backdoor` tinyint(1) UNSIGNED NOT NULL DEFAULT '0',
  `ip2root` tinyint(1) UNSIGNED DEFAULT '0',
  `ip2port` text,
  `ip2fw4ack` text,
  `ip2os4arch` varchar(200) DEFAULT NULL,
  `ip2os` text,
  `ip2asn` text,
  `ip2fw` text,
  `ip2protocol` text,
  `ip2icmp` text,
  `ip2whois` text,
  `ip2tracert` text,
  `ip2vhost` text,
  `ip4info` tinyint(1) NOT NULL DEFAULT '0',
  `ip4service` tinyint(1) NOT NULL DEFAULT '0',
  `ip4pentest` tinyint(1) NOT NULL DEFAULT '0',
  `ladate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `LAN`
--

CREATE TABLE `LAN` (
  `id` int(11) NOT NULL,
  `id8port` int(10) NOT NULL,
  `uid_name` varchar(64) DEFAULT NULL,
  `uid` int(11) DEFAULT NULL,
  `gid` int(11) DEFAULT NULL,
  `gid_name` varchar(64) DEFAULT NULL,
  `context` varchar(512) DEFAULT NULL,
  `lan2done` tinyint(1) NOT NULL DEFAULT '0',
  `id8b64` text,
  `templateB64_id` text,
  `templateB64_shell` text,
  `ladate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `PORT`
--

CREATE TABLE `PORT` (
  `id` int(10) NOT NULL,
  `id8ip` int(10) NOT NULL,
  `port` int(10) UNSIGNED DEFAULT NULL,
  `protocol` varchar(10) DEFAULT NULL,
  `port2fw` tinyint(1) DEFAULT NULL,
  `port2version` text,
  `ladate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `SERVICE`
--

CREATE TABLE `SERVICE` (
  `id` int(10) UNSIGNED NOT NULL,
  `id8port` int(11) NOT NULL,
  `service2name` varchar(64) DEFAULT NULL,
  `service2version` varchar(64) DEFAULT NULL,
  `service2product` varchar(64) DEFAULT NULL,
  `service2extrainfo` varchar(256) DEFAULT NULL,
  `service2hostname` varchar(256) DEFAULT NULL,
  `service2conf` int(3) DEFAULT NULL,
  `service2ostype` varchar(64) DEFAULT NULL,
  `service2banner` varchar(512) DEFAULT NULL,
  `ladate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COMMENT='Services Enumertion';

-- --------------------------------------------------------

--
-- Table structure for table `URI`
--

CREATE TABLE `URI` (
  `id` int(11) NOT NULL,
  `id8port` int(10) NOT NULL,
  `vhost` varchar(64) DEFAULT NULL,
  `path` varchar(512) DEFAULT NULL,
  `param` varchar(512) DEFAULT NULL,
  `param2hash` varchar(64) DEFAULT NULL,
  `param2fi` tinyint(4) DEFAULT '0',
  `param2sqli` tinyint(4) DEFAULT '0',
  `param2ce` tinyint(4) DEFAULT '0',
  `param2xss` tinyint(4) DEFAULT '0',
  `ladate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Table structure for table `USERS`
--

CREATE TABLE `USERS` (
  `id` int(11) NOT NULL,
  `id8port` int(10) NOT NULL,
  `user2name` varchar(256) CHARACTER SET utf8 DEFAULT NULL,
  `user2methode` varchar(256) CHARACTER SET utf8 DEFAULT NULL,
  `user2infos` text CHARACTER SET utf8,
  `ladate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `WEB`
--

CREATE TABLE `WEB` (
  `id` int(11) NOT NULL,
  `id8port` int(10) NOT NULL,
  `vhost` varchar(64) DEFAULT NULL,
  `web2urls` longtext,
  `web2dico` longtext,
  `web2enum` text,
  `web2cms` text,
  `web2scan4cli` text,
  `web4info` tinyint(1) UNSIGNED NOT NULL DEFAULT '0',
  `web4service` tinyint(1) UNSIGNED NOT NULL DEFAULT '0',
  `web4pentest` tinyint(1) UNSIGNED NOT NULL DEFAULT '0',
  `ladate` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `AUTH`
--
ALTER TABLE `AUTH`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id8port` (`id8port`);

--
-- Indexes for table `CIDR`
--
ALTER TABLE `CIDR`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `DOMAIN`
--
ALTER TABLE `DOMAIN`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `ETH`
--
ALTER TABLE `ETH`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `IP`
--
ALTER TABLE `IP`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id8domain` (`id8domain`);

--
-- Indexes for table `LAN`
--
ALTER TABLE `LAN`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id8port` (`id8port`);

--
-- Indexes for table `PORT`
--
ALTER TABLE `PORT`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id8ip` (`id8ip`);

--
-- Indexes for table `SERVICE`
--
ALTER TABLE `SERVICE`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id8port` (`id8port`);

--
-- Indexes for table `URI`
--
ALTER TABLE `URI`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id8port` (`id8port`);

--
-- Indexes for table `USERS`
--
ALTER TABLE `USERS`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id8port` (`id8port`);

--
-- Indexes for table `WEB`
--
ALTER TABLE `WEB`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id8port` (`id8port`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `AUTH`
--
ALTER TABLE `AUTH`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `CIDR`
--
ALTER TABLE `CIDR`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `DOMAIN`
--
ALTER TABLE `DOMAIN`
  MODIFY `id` int(10) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `ETH`
--
ALTER TABLE `ETH`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `IP`
--
ALTER TABLE `IP`
  MODIFY `id` int(10) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `LAN`
--
ALTER TABLE `LAN`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `PORT`
--
ALTER TABLE `PORT`
  MODIFY `id` int(10) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `SERVICE`
--
ALTER TABLE `SERVICE`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `URI`
--
ALTER TABLE `URI`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `USERS`
--
ALTER TABLE `USERS`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `WEB`
--
ALTER TABLE `WEB`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
--
-- Constraints for dumped tables
--

--
-- Constraints for table `AUTH`
--
ALTER TABLE `AUTH`
  ADD CONSTRAINT `AUTH_USER` FOREIGN KEY (`id8port`) REFERENCES `PORT` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `IP`
--
ALTER TABLE `IP`
  ADD CONSTRAINT `IP_DOMAIN` FOREIGN KEY (`id8domain`) REFERENCES `DOMAIN` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `LAN`
--
ALTER TABLE `LAN`
  ADD CONSTRAINT `LAN_SHELL` FOREIGN KEY (`id8port`) REFERENCES `PORT` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `PORT`
--
ALTER TABLE `PORT`
  ADD CONSTRAINT `PORT_IP` FOREIGN KEY (`id8ip`) REFERENCES `IP` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `SERVICE`
--
ALTER TABLE `SERVICE`
  ADD CONSTRAINT `SERVICE_PORT` FOREIGN KEY (`id8port`) REFERENCES `PORT` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `URI`
--
ALTER TABLE `URI`
  ADD CONSTRAINT `URI_PORT` FOREIGN KEY (`id8port`) REFERENCES `PORT` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `USERS`
--
ALTER TABLE `USERS`
  ADD CONSTRAINT `USERS_PORT` FOREIGN KEY (`id8port`) REFERENCES `PORT` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `WEB`
--
ALTER TABLE `WEB`
  ADD CONSTRAINT `WEB_PORT` FOREIGN KEY (`id8port`) REFERENCES `PORT` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
