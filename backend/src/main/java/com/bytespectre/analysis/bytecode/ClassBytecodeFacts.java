package com.bytespectre.analysis.bytecode;

import com.bytespectre.analysis.model.ClassRelationship;
import com.bytespectre.analysis.model.ChannelFinding;
import com.bytespectre.analysis.model.MethodCallEdge;
import java.util.ArrayList;
import java.util.List;

public class ClassBytecodeFacts {
    private String className;
    private String packageName;
    private int methodCount;
    private int fieldCount;
    private int stringConstantCount;
    private final List<String> stringConstants = new ArrayList<>();
    private final List<ClassRelationship> relationships = new ArrayList<>();
    private final List<MethodCallEdge> methodCalls = new ArrayList<>();
    private final List<ChannelFinding> channelFindings = new ArrayList<>();
    private boolean usesReflection;
    private boolean usesClassLoader;
    private boolean usesInstrumentation;
    private boolean usesNetworking;
    private boolean usesNativeAccess;
    private boolean usesProcessExecution;
    private boolean hasPacketSignals;
    private boolean hasMinecraftSignals;
    private boolean hasMixinSignals;

    public String className() {
        return className;
    }

    public void className(String className) {
        this.className = className;
        int split = className.lastIndexOf('.');
        this.packageName = split > 0 ? className.substring(0, split) : "";
    }

    public String packageName() {
        return packageName;
    }

    public int methodCount() {
        return methodCount;
    }

    public void methodCount(int methodCount) {
        this.methodCount = methodCount;
    }

    public int fieldCount() {
        return fieldCount;
    }

    public void fieldCount(int fieldCount) {
        this.fieldCount = fieldCount;
    }

    public int stringConstantCount() {
        return stringConstantCount;
    }

    public void stringConstantCount(int stringConstantCount) {
        this.stringConstantCount = stringConstantCount;
    }

    public List<String> stringConstants() {
        return stringConstants;
    }

    public List<ClassRelationship> relationships() {
        return relationships;
    }

    public List<MethodCallEdge> methodCalls() {
        return methodCalls;
    }

    public List<ChannelFinding> channelFindings() {
        return channelFindings;
    }

    public boolean usesReflection() {
        return usesReflection;
    }

    public void usesReflection(boolean usesReflection) {
        this.usesReflection = usesReflection;
    }

    public boolean usesClassLoader() {
        return usesClassLoader;
    }

    public void usesClassLoader(boolean usesClassLoader) {
        this.usesClassLoader = usesClassLoader;
    }

    public boolean usesInstrumentation() {
        return usesInstrumentation;
    }

    public void usesInstrumentation(boolean usesInstrumentation) {
        this.usesInstrumentation = usesInstrumentation;
    }

    public boolean usesNetworking() {
        return usesNetworking;
    }

    public void usesNetworking(boolean usesNetworking) {
        this.usesNetworking = usesNetworking;
    }

    public boolean usesNativeAccess() {
        return usesNativeAccess;
    }

    public void usesNativeAccess(boolean usesNativeAccess) {
        this.usesNativeAccess = usesNativeAccess;
    }

    public boolean usesProcessExecution() {
        return usesProcessExecution;
    }

    public void usesProcessExecution(boolean usesProcessExecution) {
        this.usesProcessExecution = usesProcessExecution;
    }

    public boolean hasPacketSignals() {
        return hasPacketSignals;
    }

    public void hasPacketSignals(boolean hasPacketSignals) {
        this.hasPacketSignals = hasPacketSignals;
    }

    public boolean hasMinecraftSignals() {
        return hasMinecraftSignals;
    }

    public void hasMinecraftSignals(boolean hasMinecraftSignals) {
        this.hasMinecraftSignals = hasMinecraftSignals;
    }

    public boolean hasMixinSignals() {
        return hasMixinSignals;
    }

    public void hasMixinSignals(boolean hasMixinSignals) {
        this.hasMixinSignals = hasMixinSignals;
    }
}
