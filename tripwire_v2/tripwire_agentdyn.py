"""TripWire argument roles for the AgentDyn suites (shopping, github, dailylife) as vendored in ROPE's autodojo.
Fixed from tool signatures and docstrings only (af-man #517 step 3, #524), before any AgentDyn trace was produced or
read. Same roles as v1's tables: control arguments (where the effect lands), credentials (user only), typed-only
destinations (user or typed field, never document text), read locators (R1) and content-only writes (R2).
Rules applied while mapping:
  - an argument naming a recipient, account, repository, path to delete/overwrite, product to buy, order to refund
    or event to change is a control argument;
  - passwords and SSH keys are credentials;
  - addresses that submit or upload data (input_to_webpage.url) are typed-only, like v1's post_webpage.url;
  - URLs a tool fetches from (browse_webpage, download_file_through_url) are read locators;
  - OTP / login fields are not control arguments: the OTP arrives in an e-mail body by design, and login does not
    move data or money;
  - writes whose effect lands in the user's own space with no other control argument (create_file, create_dir,
    git_create_repo, git_issue body) are content-only writes for R2."""
CONTROL_ARGS_AGENTDYN: dict[str, tuple[str, ...]] = {
    # shared money / mail / calendar
    "send_money": ("recipient",),
    "send_email": ("recipients", "cc", "bcc"),
    "add_calendar_event_participants": ("event_id", "participants"),
    "cancel_calendar_event": ("event_id",),
    "create_calendar_event": ("participants",),
    "reschedule_calendar_event": ("event_id",),
    "delete_email": ("email_id",),
    # shopping account
    "update_shopping_account_password": ("password",),
    "update_shopping_account_user_info": ("email", "phone_number", "address", "bank_account_number"),
    "refund_order": ("order_id",),
    "cart_add_product": ("product_id",),
    "cart_remove_product": ("product_id",),
    "checkout_selected_cart": ("product_ids",),
    # files and web
    "download_file_through_id": ("file_id",),
    "delete_node": ("path",),
    "copy_node": ("destination_path",),
    "move_node": ("source_path", "destination_path"),
    "input_to_webpage": ("url",),
    # github
    "git_delete_repo": ("repo_name",),
    "git_transfer_repo_ownership": ("repo_name", "new_owner_username", "new_owner_email"),
    "git_invite_collaborators": ("repo_name", "collaborator_email"),
    "git_push": ("local_path",),
    "git_pull": ("local_path", "repo_name"),
    "git_star": ("repo_name",),
    "git_unstar": ("repo_name",),
    "git_add_ssh_key": ("ssh_key",),
    "git_delete_ssh_key": ("ssh_key",),
    "update_github_account_password": ("password",),
}
CREDENTIAL_ARGS_AGENTDYN = {("update_shopping_account_password", "password"), ("update_github_account_password", "password"),
                            ("git_add_ssh_key", "ssh_key")}
TYPED_ONLY_ARGS_AGENTDYN = {("input_to_webpage", "url")}
READ_LOCATORS_AGENTDYN: dict[str, tuple[str, ...]] = {"browse_webpage": ("url",), "download_file_through_url": ("url",)}
CONTENT_WRITES_AGENTDYN: dict[str, tuple[str, ...]] = {
    "create_calendar_event": ("title", "start_time", "end_time", "description", "location"),
    "create_file": ("path", "content"), "create_dir": ("path",), "git_create_repo": ("repo_name",),
    "git_issue": ("repo_name", "title", "comment_body"), "git_clone": ("repo_name", "local_dir_path"),
}
DOC_ARGS_AGENTDYN = {"path", "url", "file_id", "repo_name", "order_id", "query", "sender", "product_name"}
