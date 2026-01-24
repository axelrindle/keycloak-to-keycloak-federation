import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    kotlin("jvm") version "2.2.21"
    id("com.gradleup.shadow") version "9.3.1"
}

group = "de.axelrindle"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly(libs.bundles.keycloak)

    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(21)
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.withType<ProcessResources> {
    from("LICENSE")
}

tasks.withType<ShadowJar> {
    minimize()

    relocationPrefix = "ktkf_deps"
    enableAutoRelocation = true
}

