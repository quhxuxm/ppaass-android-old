package com.ppaass.agent.jni;

public class ExampleNativeObject {
    private String name;
    private int age;

    public ExampleNativeObject(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getAge() {
        return age;
    }

    public void setAge(int age) {
        this.age = age;
    }

    @Override
    public String toString() {
        return "ExampleNativeObject{" +
                "name='" + name + '\'' +
                ", age=" + age +
                '}';
    }
}
