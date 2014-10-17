create database hashes;
use hashes;
grant all privileges on hashes.* to hashes@localhost identified by 'hashes';

--
-- Table structure for table `candidates`
--

DROP TABLE IF EXISTS `candidates`;
CREATE TABLE `candidates` (
  `r` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`r`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Table structure for table `failed`
--

DROP TABLE IF EXISTS `failed`;
CREATE TABLE `failed` (
  `r` varchar(64) NOT NULL DEFAULT '',
  PRIMARY KEY (`r`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Table structure for table `hashes`
--

DROP TABLE IF EXISTS `hashes`;
CREATE TABLE `hashes` (
  `tx` varchar(64) NOT NULL,
  `r` varchar(64) NOT NULL,
  `s` varchar(64) NOT NULL,
  `hash` varchar(64) NOT NULL,
  UNIQUE KEY `rs` (`r`,`s`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Table structure for table `privkeys`
--

DROP TABLE IF EXISTS `privkeys`;
CREATE TABLE `privkeys` (
  `hexprivkey` varchar(64) NOT NULL DEFAULT '',
  `privkey` varchar(51) DEFAULT NULL,
  UNIQUE KEY `hexprivkey` (`hexprivkey`,`privkey`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
