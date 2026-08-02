plugins {
    `java-library`
}

group = "dev.pqm"
version = "0.2.0"

repositories {
    mavenCentral()
}

dependencies {
    runtimeOnly("org.bouncycastle:bcprov-jdk18on:1.84")
    testImplementation(platform("org.junit:junit-bom:5.12.2"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    withSourcesJar()
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Werror"))
}
