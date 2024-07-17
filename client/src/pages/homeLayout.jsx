import { Outlet } from 'react-router-dom'
import Header from '../component/Header'
import Footer from '../component/Footer'

const HomeLayout = () => {
  return (
    <>
    <Header />
    <Outlet />
    <Footer />
    </>
  )
}

export default HomeLayout;