/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.otherProfile1",
  "idor.hints.otherProfile2",
  "idor.hints.otherProfile3",
  "idor.hints.otherProfile4",
  "idor.hints.otherProfile5",
  "idor.hints.otherProfile6",
  "idor.hints.otherProfile7",
  "idor.hints.otherProfile8",
  "idor.hints.otherProfile9"
})
public class IDOREditOtherProfile implements AssignmentEndpoint {

  private final LessonSession userSessionData;

  public IDOREditOtherProfile(LessonSession lessonSession) {
    this.userSessionData = lessonSession;
  }

  @PutMapping(path = "/IDOR/profile/{userId}", consumes = "application/json")
  @ResponseBody
  public AttackResult completed(
      @PathVariable("userId") String userId, @RequestBody UserProfile userSubmittedProfile) {

    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");

    if (authUserId == null) {
      return failed(this).feedback("idor.edit.profile.failure3").build();
    }

    // Authorization check: only allow users to edit their own profile
    if (!userId.equals(authUserId)) {
      // The user is attempting to edit another user's profile (IDOR attack).
      // Evaluate whether they submitted the correct exploit payload for the lesson,
      // but do NOT actually persist the modification.
      if (userSubmittedProfile.getUserId() != null
          && !userSubmittedProfile.getUserId().equals(authUserId)) {
        if (userSubmittedProfile.getRole() <= 1
            && userSubmittedProfile.getColor() != null
            && userSubmittedProfile.getColor().equalsIgnoreCase("red")) {
          return success(this)
              .feedback("idor.edit.profile.success1")
              .build();
        }

        if (userSubmittedProfile.getRole() > 1
            && userSubmittedProfile.getColor() != null
            && userSubmittedProfile.getColor().equalsIgnoreCase("red")) {
          return failed(this).feedback("idor.edit.profile.failure1").build();
        }

        if (userSubmittedProfile.getRole() <= 1
            && (userSubmittedProfile.getColor() == null
                || !userSubmittedProfile.getColor().equalsIgnoreCase("red"))) {
          return failed(this).feedback("idor.edit.profile.failure2").build();
        }

        return failed(this).feedback("idor.edit.profile.failure3").build();
      }
      return failed(this).feedback("idor.edit.profile.failure3").build();
    }

    // User is editing their own profile
    if (userSubmittedProfile.getUserId() != null
        && userSubmittedProfile.getUserId().equals(authUserId)) {
      return failed(this).feedback("idor.edit.profile.failure4").build();
    }

    UserProfile currentUserProfile = new UserProfile(userId);
    if (currentUserProfile.getColor().equals("black") && currentUserProfile.getRole() <= 1) {
      return success(this)
          .feedback("idor.edit.profile.success2")
          .output(userSessionData.getValue("idor-updated-own-profile").toString())
          .build();
    } else {
      return failed(this).feedback("idor.edit.profile.failure3").build();
    }
  }
}
