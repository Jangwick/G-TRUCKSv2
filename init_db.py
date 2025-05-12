from app import app, db, User, Barangay
from werkzeug.security import generate_password_hash

def init_database():
    """Initialize database with required tables and sample data"""
    print("Creating database tables...")
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if admin exists
        admin = User.query.filter_by(user_type='admin').first()
        if not admin:
            # Create admin user
            print("Creating admin user...")
            admin = User(
                username='admin',
                email='admin@gtrucks.com',
                password=generate_password_hash('admin123'),
                user_type='admin'
            )
            db.session.add(admin)
            
            # Create districts and sample barangays
            print("Creating sample barangay data...")
            districts = {
                1: ["Alicia", "Bagong Pag-asa", "Bahay Toro", "Balingasa", "Damar", "Damayan", "Katipunan", "Mariblo", "Masambong", "Paltok", "Paraiso", "Phil-Am", "Project 6", "Ramon Magsaysay", "Saint Peter", "Talayan", "Tandang Sora", "Veterans Village", "West Triangle"],
                2: ["Bagumbayan", "Baesa", "Banlat", "Capri", "Central", "Commonwealth", "Culiat", "Damayang Lagi", "E. Rodriguez", "East Kamias", "Escopa 1", "Escopa 2", "Escopa 3", "Escopa 4", "Fair View", "Kalusugan", "Kamuning", "Kaunlaran", "Kristong Hari", "Krus Na Ligas", "Laging Handa", "Mangga", "Mariana", "Masagana", "Milagrosa", "New Era", "Novaliches Proper", "Obrero", "Old Capitol Site", "Pag-ibig sa Nayon", "Paligsahan", "Pinyahan", "Quirino 2-A", "Quirino 2-B", "Quirino 2-C", "Quirino 3-A", "Roxas", "Sacred Heart", "Saint Ignatius", "Salvacion", "San Isidro Galas", "San Jose", "San Martin de Porres", "San Roque", "Santa Cruz", "Santa Teresita", "Santo Domingo", "Santol", "Sienna", "Silangan", "Socorro", "South Triangle", "Tagumpay", "Teacher's Village East", "Teacher's Village West", "U.P. Campus", "U.P. Village", "Ugong Norte", "Valencia", "West Kamias"],
                3: ["Amihan", "Bagumbuhay", "Bagong Lipunan", "Bagong Silangan", "Batasan Hills", "Claro", "Commonwealth", "Fairview", "Nagkaisang Nayon", "Pasong Putik", "Payatas", "Matandang Balara", "Vatican", "Loyola Heights"],
                4: ["Bagong Silang", "Nagkaisang Nayon", "Novaliches Proper", "Pasong Putik", "Gulod", "Sta. Monica", "Kaligayahan", "Greater Lagro", "North Fairview", "Fairview", "San Agustin", "San Bartolome", "Tullahan"],
                5: ["Bagbag", "Capri", "Fairview", "Greater Lagro", "Guilod", "Kaligayahan", "Nagkaisang Nayon", "Novaliches Proper", "Pasong Putik", "San Bartolome", "Santa Lucia", "Santa Monica", "San Agustin"],
                6: ["Apolonio Samson", "Baesa", "Balumbato", "Culiat", "New Era", "Pasong Tamo", "Sangandaan", "Sauyo", "Talipapa", "Tandang Sora", "Unang Sigaw"]
            }
            
            for district, barangays in districts.items():
                for barangay_name in barangays:
                    barangay = Barangay(name=barangay_name, district=district)
                    db.session.add(barangay)
            
            db.session.commit()
            print("Database initialization complete!")
        else:
            print("Admin user already exists. Database already initialized.")

if __name__ == '__main__':
    init_database()
