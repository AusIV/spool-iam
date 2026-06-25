from django.contrib import admin

from .models import (
    AuditLog,
    IssuedToken,
    Policy,
    Principal,
    PrincipalRole,
    RefreshToken,
    Role,
    RolePolicy,
)


class RolePolicyInline(admin.TabularInline):
    model = RolePolicy
    extra = 0


class PrincipalRoleInline(admin.TabularInline):
    model = PrincipalRole
    extra = 0


@admin.register(Policy)
class PolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "created_at", "updated_at")
    search_fields = ("name",)


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("name", "created_at", "updated_at")
    search_fields = ("name",)
    inlines = [RolePolicyInline]


@admin.register(Principal)
class PrincipalAdmin(admin.ModelAdmin):
    list_display = ("name", "principal_type", "user", "created_at", "updated_at")
    list_filter = ("principal_type",)
    search_fields = ("name", "user__username", "user__email")
    inlines = [PrincipalRoleInline]


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "principal",
        "actor_principal",
        "action",
        "resource",
        "allowed",
        "reason",
        "exported_at",
    )
    list_filter = ("allowed", "reason", "exported_at", "created_at")
    search_fields = (
        "principal__name",
        "user__username",
        "actor_principal__name",
        "actor_user__username",
        "action",
        "resource",
    )
    readonly_fields = (
        "principal",
        "user",
        "actor_principal",
        "actor_user",
        "action",
        "resource",
        "context",
        "allowed",
        "reason",
        "matched_statements",
        "created_at",
        "exported_at",
        "export_path",
    )

    def has_add_permission(self, request):
        return False


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "user",
        "family_id",
        "generation",
        "refreshes_remaining",
        "expires_at",
        "used_at",
        "revoked_at",
    )
    list_filter = ("expires_at", "used_at", "revoked_at", "created_at")
    search_fields = ("user__username", "family_id", "token_hash")
    readonly_fields = (
        "user",
        "token_hash",
        "family_id",
        "generation",
        "parent",
        "refreshes_remaining",
        "expires_at",
        "used_at",
        "revoked_at",
        "created_at",
    )

    def has_add_permission(self, request):
        return False


@admin.register(IssuedToken)
class IssuedTokenAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "user",
        "token_type",
        "subject",
        "family_id",
        "generation",
        "expires_at",
        "revoked_at",
    )
    list_filter = ("token_type", "expires_at", "revoked_at", "created_at")
    search_fields = ("user__username", "subject", "family_id", "jti")
    readonly_fields = (
        "jti",
        "user",
        "token_type",
        "subject",
        "family_id",
        "generation",
        "expires_at",
        "revoked_at",
        "created_at",
    )

    def has_add_permission(self, request):
        return False
