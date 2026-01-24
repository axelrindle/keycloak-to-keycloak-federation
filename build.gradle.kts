import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

plugins {
    kotlin("jvm") version "2.2.21"
    id("com.gradleup.shadow") version "9.3.1"
}

fun String.exec(): String {
    val proc = ProcessBuilder(*this.split(" ").toTypedArray())
        .redirectOutput(ProcessBuilder.Redirect.PIPE)
        .redirectError(ProcessBuilder.Redirect.DISCARD)
        .start()

    proc.waitFor(10, TimeUnit.SECONDS)
    return proc.inputReader().buffered().readText().trim()
}

fun isDirty(): Boolean {
    val result = "git status --untracked-files=no --porcelain".exec()
    return result.isNotBlank()
}

fun getVersion(): String {
    val tag = "git tag --points-at HEAD".exec()
    if (tag.isNotBlank()) {
        return tag
    }

    val commit = "git rev-parse --short HEAD".exec()
    val isDirty = isDirty()

    if (isDirty) {
        return "$commit-SNAPSHOT"
    }

    return commit
}

group = "de.axelrindle"
version = getVersion()

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

