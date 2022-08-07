CREATE TABLE IF NOT EXISTS `requests` (
  `digest` TEXT NOT NULL,
  `request` BLOB NOT NULL,
  PRIMARY KEY (`digest`)
);
CREATE TABLE IF NOT EXISTS `pre_prepares` (
  `view` INT NOT NULL,
  `seq` INT NOT NULL,
  `pre_prepare` BLOB NOT NULL,
  PRIMARY KEY (`view`, `seq`)
);
CREATE TABLE IF NOT EXISTS `prepares_with_commits` (
  `view` INT NOT NULL,
  `seq` INT NOT NULL,
  `digest` TEXT NOT NULL,
  `prepare` BLOB NOT NULL,
  `prepare_replicas` TEXT NOT NULL,
  `commit` BLOB NOT NULL,
  `commit_replicas` TEXT NOT NULL,
  PRIMARY KEY (`view`, `seq`, `digest`),
  FOREIGN KEY (`view`, `seq`) REFERENCES `pre_prepares` (`view`, `seq`),
  FOREIGN KEY (`digest`) REFERENCES `requests` (`digest`)
);