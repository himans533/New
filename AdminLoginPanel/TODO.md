# TODO: Update Employee Dashboard for Project Display in Overview

## Tasks to Complete

- [ ] Modify Overview's Recent Activity section to display 5 most recent projects (sorted by created_at descending)
- [ ] Add "View Details" and "Edit" buttons to each project card in Recent Activity
- [ ] Add new modals: viewProjectModal for displaying project details and editProjectModal for editing projects
- [ ] Add JavaScript functions: renderRecentProjects(), openViewProjectModal(), openEditProjectModal(), viewProject(), editProject()
- [ ] Update loadDashboardData() to call renderRecentProjects() after loading projects
- [ ] Ensure edit functionality checks for 'Proj' Edit permission
- [ ] Add API calls for fetching single project details (for edit prefill) and updating project
