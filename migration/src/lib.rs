pub use sea_orm_migration::prelude::*;

mod m20230126_094452_create_tasks_table;
mod m20230127_123220_create_users_table;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230127_123220_create_users_table::Migration),
            Box::new(m20230126_094452_create_tasks_table::Migration),
        ]
    }
}
