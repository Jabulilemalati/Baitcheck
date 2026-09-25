package com.baitcheck.analysis;

import com.baitcheck.model.Email;

import java.util.List;

public interface Analyzer {

    List<Finding> analyze(Email email);
}
