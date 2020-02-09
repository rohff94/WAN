#include <stdio.h>
#include <unistd.h>
int main()
{
uid_t user_id;
uid_t eff_user_id;
gid_t group_id;
gid_t eff_group_id;

user_id = getuid();
eff_user_id = geteuid();
group_id = getgid();
eff_group_id = getegid();

printf("User Id: %ld, Group Id: %ld \n", user_id, group_id);
printf("Eff User Id: %ld, Eff Group Id: %ld \n", eff_user_id, eff_group_id);

return 0;
}
