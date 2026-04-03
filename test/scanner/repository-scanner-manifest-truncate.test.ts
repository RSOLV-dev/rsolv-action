import { describe, it, expect } from 'vitest';
import { RepositoryScanner } from '../../src/scanner/repository-scanner.js';

/**
 * Tests for manifest file truncation when files exceed 10KB cap.
 * Addresses WebGoat pom.xml (30KB) exceeding manifest capture limit.
 */
describe('RepositoryScanner.truncateManifest', () => {
  describe('pom.xml', () => {
    it('extracts <dependencies> block from oversized pom.xml', () => {
      const pomXml = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.owasp.webgoat</groupId>
  <artifactId>webgoat</artifactId>
  <version>2023.8</version>
  <packaging>pom</packaging>

  <modules>
    <module>webgoat-container</module>
    <module>webgoat-lessons</module>
  </modules>

  <properties>
    <java.version>17</java.version>
    <spring-boot.version>3.1.0</spring-boot.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
      <groupId>com.h2database</groupId>
      <artifactId>h2</artifactId>
      <scope>runtime</scope>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
</project>`;

      const result = RepositoryScanner.truncateManifest('pom.xml', pomXml);

      expect(result).not.toBeNull();
      expect(result).toContain('spring-boot-starter-data-jpa');
      expect(result).toContain('h2');
      // Should NOT contain build plugin config
      expect(result).not.toContain('<plugins>');
      expect(result).not.toContain('<modules>');
    });

    it('extracts multiple <dependencies> blocks', () => {
      const pomXml = `<project>
  <dependencies>
    <dependency>
      <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
  </dependencies>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <artifactId>postgresql</artifactId>
        <version>42.6.0</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>`;

      const result = RepositoryScanner.truncateManifest('pom.xml', pomXml);

      expect(result).not.toBeNull();
      expect(result).toContain('spring-boot-starter-data-jpa');
      expect(result).toContain('postgresql');
    });

    it('returns null for pom.xml without dependencies block', () => {
      const pomXml = `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <modules><module>child</module></modules>
</project>`;

      const result = RepositoryScanner.truncateManifest('pom.xml', pomXml);
      expect(result).toBeNull();
    });

    it('handles nested path like subdir/pom.xml', () => {
      const pomXml = `<project>
  <dependencies>
    <dependency><artifactId>h2</artifactId></dependency>
  </dependencies>
</project>`;

      // truncateManifest extracts filename, so subdir/pom.xml still matches
      const result = RepositoryScanner.truncateManifest('webgoat-server/pom.xml', pomXml);
      expect(result).not.toBeNull();
      expect(result).toContain('h2');
    });
  });

  describe('build.gradle', () => {
    it('extracts dependencies block from oversized build.gradle', () => {
      const gradle = `plugins {
    id 'org.springframework.boot' version '3.1.0'
    id 'io.spring.dependency-management' version '1.1.0'
    id 'java'
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    runtimeOnly 'com.h2database:h2'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
}

tasks.named('test') {
    useJUnitPlatform()
}`;

      const result = RepositoryScanner.truncateManifest('build.gradle', gradle);

      expect(result).not.toBeNull();
      expect(result).toContain('spring-boot-starter-data-jpa');
      expect(result).toContain('h2');
      // Should NOT contain plugins or repositories
      expect(result).not.toContain('mavenCentral');
      expect(result).not.toContain("id 'java'");
    });

    it('handles nested braces in dependencies block', () => {
      const gradle = `dependencies {
    implementation('org.springframework.boot:spring-boot-starter-data-jpa') {
        exclude group: 'org.apache.tomcat'
    }
    runtimeOnly 'com.h2database:h2'
}`;

      const result = RepositoryScanner.truncateManifest('build.gradle', gradle);

      expect(result).not.toBeNull();
      expect(result).toContain('spring-boot-starter-data-jpa');
      expect(result).toContain('h2');
      expect(result).toContain('exclude group');
    });

    it('returns null for build.gradle without dependencies block', () => {
      const gradle = `plugins {
    id 'java'
}
repositories {
    mavenCentral()
}`;

      const result = RepositoryScanner.truncateManifest('build.gradle', gradle);
      expect(result).toBeNull();
    });
  });

  describe('unsupported file types', () => {
    it('returns null for Gemfile', () => {
      expect(RepositoryScanner.truncateManifest('Gemfile', 'gem "rails"')).toBeNull();
    });

    it('returns null for package.json', () => {
      expect(RepositoryScanner.truncateManifest('package.json', '{"name":"app"}')).toBeNull();
    });

    it('returns null for unknown file', () => {
      expect(RepositoryScanner.truncateManifest('unknown.txt', 'content')).toBeNull();
    });
  });
});
